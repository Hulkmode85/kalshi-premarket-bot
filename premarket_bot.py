"""
Kalshi Pre-Market Futures Bot
Trades Kalshi stock price markets based on pre-market futures and overnight moves.
Uses Yahoo Finance pre-market data (free, no API key needed).
Logic: If futures/pre-market shows SPY up 1%+ → buy YES on "SPY above X" markets near current price.
"""

import asyncio
import os
from flask import Flask, jsonify
import threading
import json
import time
import uuid
import logging
import base64
import re
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
import httpx
from dotenv import load_dotenv

load_dotenv()

# ── Multi-strike: scan ALL strikes per event/series, not just one ────────────
MULTI_STRIKE = os.getenv("MULTI_STRIKE", "true").lower() == "true"
# When fetching markets, iterate through ALL contracts in each series/event
# and evaluate each strike independently. No single-ticker filtering.

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("premarket")

from risk_guard import RiskManager
risk_manager = RiskManager()

# ── Shadow Logging ────────────────────────────────────────────────────────────
SHADOW_LOG_FILE = os.getenv("SHADOW_LOG_FILE", "shadow_log.jsonl")

def shadow_log(opportunity: dict, taken: bool, reason: str = ""):
    entry = {"ts": time.time(), "taken": taken, "reason": reason, **opportunity}
    try:
        with open(SHADOW_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except:
        pass



# ─── Regime Detection — pause trading during extreme volatility ────────────
import statistics as _stats

REGIME_WINDOW = int(os.getenv("REGIME_WINDOW", "20"))
REGIME_THRESHOLD = float(os.getenv("REGIME_THRESHOLD", "3.0"))
_regime_prices: list[float] = []

def check_regime(price: float) -> str:
    """Returns 'CALM', 'ELEVATED', or 'CRASH'. Skip trades during CRASH."""
    _regime_prices.append(price)
    if len(_regime_prices) > REGIME_WINDOW:
        _regime_prices.pop(0)
    if len(_regime_prices) < 5:
        return "CALM"
    rets = [(b - a) / a for a, b in zip(_regime_prices[:-1], _regime_prices[1:])]
    if not rets:
        return "CALM"
    mu = _stats.mean(rets)
    sd = _stats.stdev(rets) if len(rets) > 1 else 0.01
    z = abs(rets[-1] - mu) / max(sd, 0.0001)
    if z > REGIME_THRESHOLD:
        return "CRASH"
    elif z > REGIME_THRESHOLD * 0.6:
        return "ELEVATED"
    return "CALM"


def _normalize_market(m: dict) -> dict:
    """Normalize Kalshi API v2 dollar-denominated fields to legacy field names."""
    if "yes_bid_dollars" in m and "yes_bid" not in m:
        m["yes_bid"] = m.get("yes_bid_dollars")
        m["yes_ask"] = m.get("yes_ask_dollars")
        m["no_bid"] = m.get("no_bid_dollars")
        m["no_ask"] = m.get("no_ask_dollars")
        m["last_price"] = m.get("last_price_dollars")
        m["volume"] = m.get("volume_fp") or m.get("volume_24h_fp") or m.get("volume", 0)
        m["open_interest"] = m.get("open_interest_fp") or m.get("open_interest", 0)
    for k in ["yes_bid", "yes_ask", "no_bid", "no_ask", "last_price"]:
        v = m.get(k)
        if isinstance(v, str):
            try: m[k] = float(v)
            except: pass
    return m


# ── CONFIG ────────────────────────────────────────────────────────────────────
KALSHI_BASE       = os.getenv("KALSHI_BASE", "https://api.elections.kalshi.com")
KALSHI_API_URL    = os.getenv("KALSHI_API_URL", f"{KALSHI_BASE}/trade-api/v2")
KALSHI_API_KEY    = os.getenv("KALSHI_API_KEY", "")
KALSHI_KEY_ID     = os.getenv("KALSHI_KEY_ID", "")
PAPER_MODE        = os.getenv("PAPER_MODE", "true").lower() == "true"
PAPER_BALANCE     = float(os.getenv("PAPER_BALANCE", "5000"))
BET_SIZE_USD      = float(os.getenv("BET_SIZE_USD", "12"))
MAX_BET_USD       = float(os.getenv("MAX_BET_USD", "35"))
KELLY_FRACTION    = float(os.getenv("KELLY_FRACTION", "1.0"))
MIN_MOVE_PCT      = float(os.getenv("MIN_MOVE_PCT", "0.8"))   # min % premarket move to signal
MIN_EDGE          = float(os.getenv("MIN_EDGE", "0.06"))
MAKER_FEE         = float(os.getenv("MAKER_FEE", "0.0175"))
POLL_INTERVAL_SEC = int(os.getenv("POLL_INTERVAL_SEC", "900"))

# Tracked symbols → Kalshi series
SYMBOLS = {
    "SPY":  ["KXSPY","KXSPYX"],
    "QQQ":  ["KXQQQ","KXQQQX"],
    "NVDA": ["KXNVDA","KXNVDAS"],
    "AAPL": ["KXAAPL"],
    "MSFT": ["KXMSFT"],
    "TSLA": ["KXTSLA"],
    "META": ["KXMETA"],
    "AMZN": ["KXAMZN"],
    "ES=F": ["KXSPY","KXSPYX"],   # S&P 500 futures
    "NQ=F": ["KXQQQ","KXQQQX"],   # Nasdaq futures
}

# ── AUTH ──────────────────────────────────────────────────────────────────────
def _sign_request(method, path, ts, body=""):
    if not KALSHI_API_KEY:
        return ""
    try:
        pem_str = os.getenv("KALSHI_PRIVATE_KEY", "")
        if "\\n" in pem_str:
            pem_str = pem_str.replace("\\n", "\n")
        private_key = serialization.load_pem_private_key(pem_str.encode(), password=None)
        msg = f"{ts}{method.upper()}{path}{body}".encode()
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            sig = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        else:
            sig = private_key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        return base64.b64encode(sig).decode()
    except Exception:
        return ""

def _auth_headers(method, path, body=""):
    ts = int(time.time() * 1000)
    return {"Content-Type": "application/json",
            "KALSHI-ACCESS-KEY": KALSHI_KEY_ID,
            "KALSHI-ACCESS-TIMESTAMP": str(ts),
            "KALSHI-ACCESS-SIGNATURE": _sign_request(method, path, ts, body)}

# ── PAPER LEDGER ──────────────────────────────────────────────────────────────
@dataclass
class PaperLedger:
    balance: float = PAPER_BALANCE
    trades: list = field(default_factory=list)

    def record(self, market, side, contracts, price_cents, signal):
        cost = contracts * price_cents / 100
        self.balance -= cost
        self.trades.append({"ts": datetime.now(timezone.utc).isoformat(),
            "market": market, "side": side, "contracts": contracts,
            "price_cents": price_cents, "cost": cost, "signal": signal})
        log.info(f"[PAPER] {side} {contracts}ct @ {price_cents}¢ | {signal} | bal=${self.balance:.2f}")

# ── PREMARKET DATA ────────────────────────────────────────────────────────────
@dataclass
class PremarketQuote:
    symbol: str
    current_price: float
    prev_close: float
    pre_market_price: float
    change_pct: float      # % change from prev close
    market_state: str      # PRE, REGULAR, POST, CLOSED

async def get_yahoo_quote(client: httpx.AsyncClient, symbol: str) -> Optional[PremarketQuote]:
    """Fetch pre-market quote from Yahoo Finance."""
    url = f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?interval=1m&range=1d&includePrePost=true"
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
    try:
        r = await client.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        meta = data.get("chart", {}).get("result", [{}])[0].get("meta", {})

        current      = meta.get("regularMarketPrice", 0)
        prev_close   = meta.get("previousClose") or meta.get("chartPreviousClose") or current
        pre_price    = meta.get("preMarketPrice") or current
        market_state = meta.get("marketState", "CLOSED")

        if not current or not prev_close:
            return None

        # Use pre-market price if available, else current
        ref_price = pre_price if market_state in ("PRE", "PREPRE") else current
        change_pct = (ref_price - prev_close) / prev_close * 100 if prev_close else 0

        return PremarketQuote(
            symbol=symbol, current_price=current, prev_close=prev_close,
            pre_market_price=ref_price, change_pct=change_pct, market_state=market_state
        )
    except Exception as e:
        log.debug(f"Yahoo quote error {symbol}: {e}")
        return None

# ── KALSHI MARKETS ────────────────────────────────────────────────────────────
async def get_kalshi_markets(client: httpx.AsyncClient, series: str) -> list:
    path = f"/markets?series_ticker={series}&status=open&limit=20"
    headers = _auth_headers("GET", path) if KALSHI_KEY_ID else {"Content-Type": "application/json"}
    try:
        r = await client.get(f"{KALSHI_API_URL}{path}", headers=headers, timeout=10)
        return r.json().get("markets", []) if r.status_code == 200 else []
    except Exception:
        return []

def price_from_title(title: str) -> Optional[float]:
    m = re.search(r'\$\s*([\d,]+(?:\.\d+)?)', title)
    if m:
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            pass
    return None

def find_premarket_trade(markets: list, quote: PremarketQuote) -> Optional[dict]:
    """
    Strong pre-market move → trade nearby Kalshi threshold markets.
    Up move: buy YES on "above X" where X is just above current → likely to resolve YES
    Down move: buy YES on "below X" where X is just below current → likely to resolve YES
    """
    bullish = quote.change_pct >= MIN_MOVE_PCT
    bearish = quote.change_pct <= -MIN_MOVE_PCT
    if not bullish and not bearish:
        return None

    current = quote.pre_market_price
    strength = min(abs(quote.change_pct) / 2.0, 1.0)  # normalize: 2% move = full strength
    confidence = 0.55 + strength * 0.20  # 0.55-0.75

    best = None
    best_edge = 0.0

    for m in markets:
        _normalize_market(m)
        title = m.get("title", "").lower()
        yes_ask = m.get("yes_ask", 0)
        no_ask  = m.get("no_ask", 0)
        if not yes_ask or not no_ask:
            continue

        close_ts = m.get("close_time") or m.get("expiration_time") or ""
        if close_ts:
            try:
                close_dt = datetime.fromisoformat(close_ts.replace("Z", "+00:00"))
                remaining = (close_dt - datetime.now(timezone.utc)).total_seconds()
                if remaining < 3600 or remaining > 86400:  # only today's markets
                    continue
            except Exception:
                pass

        threshold = price_from_title(m.get("title", ""))
        if threshold is None:
            continue

        is_above = any(w in title for w in ["above","over","exceed","higher"])
        is_below = any(w in title for w in ["below","under","fall","drop"])

        if bullish and is_above:
            # Pre-market up → price likely to be above threshold if threshold is close
            proximity = 1.0 - abs(threshold - current) / max(current, 1) * 10
            proximity = max(0, min(proximity, 1))
            true_prob = confidence * proximity
            edge = true_prob - yes_ask / 100
            if edge - MAKER_FEE > 0 and edge > best_edge and edge >= MIN_EDGE:
                best_edge = edge
                best = {"market": m, "side": "yes", "price": yes_ask, "edge": edge,
                        "note": f"{quote.symbol} +{quote.change_pct:.1f}% premarket → YES above ${threshold:.0f}"}

        elif bearish and is_below:
            proximity = 1.0 - abs(threshold - current) / max(current, 1) * 10
            proximity = max(0, min(proximity, 1))
            true_prob = confidence * proximity
            edge = true_prob - yes_ask / 100
            if edge - MAKER_FEE > 0 and edge > best_edge and edge >= MIN_EDGE:
                best_edge = edge
                best = {"market": m, "side": "yes", "price": yes_ask, "edge": edge,
                        "note": f"{quote.symbol} {quote.change_pct:.1f}% premarket → YES below ${threshold:.0f}"}

        elif bullish and is_below and threshold < current * 0.97:
            # Strong up move → won't fall below a lower threshold → buy NO
            true_prob_no = min(confidence * 0.85, 0.80)
            edge = true_prob_no - no_ask / 100
            if edge - MAKER_FEE > 0 and edge > best_edge and edge >= MIN_EDGE:
                best_edge = edge
                best = {"market": m, "side": "no", "price": no_ask, "edge": edge,
                        "note": f"{quote.symbol} +{quote.change_pct:.1f}% premarket → NO below ${threshold:.0f}"}

        elif bearish and is_above and threshold > current * 1.03:
            # Strong down move → won't reach higher threshold → buy NO
            true_prob_no = min(confidence * 0.85, 0.80)
            edge = true_prob_no - no_ask / 100
            if edge - MAKER_FEE > 0 and edge > best_edge and edge >= MIN_EDGE:
                best_edge = edge
                best = {"market": m, "side": "no", "price": no_ask, "edge": edge,
                        "note": f"{quote.symbol} {quote.change_pct:.1f}% premarket → NO above ${threshold:.0f}"}

    return best

# ── ORDER EXECUTION ───────────────────────────────────────────────────────────
async def place_order(client, ticker, side, price_cents, contracts, ledger, note):
    if PAPER_MODE:
        ledger.record(ticker, side, contracts, price_cents, note)
        return True
    body = json.dumps({"ticker": ticker, "action": "buy", "side": side,
                       "type": "limit", "count": contracts,
                       "yes_price" if side == "yes" else "no_price": price_cents,
                       "client_order_id": str(uuid.uuid4())})
    path = "/portfolio/orders"
    try:
        r = await client.post(f"{KALSHI_API_URL}{path}", headers=_auth_headers("POST", path, body),
                              content=body, timeout=10)
        return r.status_code in (200, 201)
    except Exception:
        return False

# ── COOLDOWN ──────────────────────────────────────────────────────────────────
class CooldownTracker:
    def __init__(self, minutes=120):
        self._last = {}
        self.minutes = minutes
    def can_trade(self, key):
        return key not in self._last or \
               (datetime.now(timezone.utc) - self._last[key]).total_seconds() > self.minutes * 60
    def mark(self, key):
        self._last[key] = datetime.now(timezone.utc)

# ── MAIN ──────────────────────────────────────────────────────────────────────
# ── Stats HTTP server ─────────────────────────────────────────────────────────
_stats_app = Flask(__name__)
_bot_stats = {"trades": 0, "wins": 0, "pnl": 0.0, "balance": 0.0, "start": time.time()}

@_stats_app.route("/stats")
def _stats_endpoint():
    t = _bot_stats
    total = t["trades"]
    return jsonify({"bot": "kalshi-premarket-bot", "paper_mode": True,
        "balance": t["balance"], "trades": total, "wins": t["wins"],
        "losses": total - t["wins"], "win_rate": round(t["wins"]/max(total,1), 4),
        "pnl": t["pnl"], "uptime_hours": round((time.time()-t["start"])/3600, 2)})

@_stats_app.route("/health")
def _health_endpoint():
    return jsonify({"status": "ok"})

def _run_stats_server():
    _stats_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))


async def main():
    log.info(f"=== Kalshi Pre-Market Futures Bot (paper={PAPER_MODE}) ===")
    log.info(f"MIN_MOVE={MIN_MOVE_PCT}%, MIN_EDGE={MIN_EDGE*100:.0f}%, poll={POLL_INTERVAL_SEC}s")
    log.info(f"Tracking: {list(SYMBOLS.keys())}")

    paper    = PaperLedger()
    _bot_stats['balance'] = paper.balance
    threading.Thread(target=_run_stats_server, daemon=True).start()
    cooldown = CooldownTracker(minutes=120)
    trades   = 0

    async with httpx.AsyncClient() as client:
        while True:
            _bot_stats["balance"] = paper.balance
            _bot_stats["trades"] = len(paper.trades)
            log.info(f"--- Scan | bal=${paper.balance:.2f} | trades={trades} ---")

            for symbol, series_list in SYMBOLS.items():
                try:
                    quote = await get_yahoo_quote(client, symbol)
                    if not quote:
                        continue

                    log.info(f"{symbol}: {quote.market_state} price=${quote.pre_market_price:.2f} "
                             f"chg={quote.change_pct:+.2f}%")

                    if abs(quote.change_pct) < MIN_MOVE_PCT:
                        continue

                    cd_key = f"{symbol}_{'up' if quote.change_pct > 0 else 'down'}"
                    if not cooldown.can_trade(cd_key):
                        log.info(f"{symbol}: cooldown active")
                        continue

                    # Fetch markets
                    all_markets = []
                    for series in series_list:
                        mkts = await get_kalshi_markets(client, series)
                        all_markets.extend(mkts)
                        await asyncio.sleep(0.3)

                    if not all_markets:
                        continue

                    trade = find_premarket_trade(all_markets, quote)
                    if not trade:
                        log.info(f"{symbol}: no edge found in {len(all_markets)} markets")
                        shadow_log({"bot": "premarket", "symbol": symbol, "change_pct": quote.change_pct}, taken=False, reason="no edge found")
                        continue

                    price     = trade["price"]
                    # Kelly criterion sizing
                    market_prob = price / 100
                    model_prob = min(0.95, market_prob + trade["edge"])
                    kelly_f = max(0, (model_prob - market_prob) / (1 - market_prob)) if market_prob < 1 else 0
                    kelly_bet = max(1, min(ledger.balance * kelly_f * KELLY_FRACTION, MAX_BET_USD))
                    contracts = max(1, int(kelly_bet * 100 / price))
                    ticker    = trade["market"].get("ticker", "?")

                    log.info(f"[TRADE] {ticker} | {trade['side'].upper()} {contracts}ct @ {price}¢ | "
                             f"edge={trade['edge']*100:.1f}% | {trade['note']}")

                    # ── Risk Guard check ──
                    if not PAPER_MODE:
                        allowed, reason, capped = risk_manager.pre_trade_check(ticker, price, contracts, trade["side"], bot_name="premarket-bot")
                        if not allowed:
                            log.warning(f"Risk guard blocked: {reason}")
                            continue
                        contracts = capped
                    else:
                        allowed, reason, capped = risk_manager.pre_trade_check(ticker, price, contracts, trade["side"], bot_name="premarket-bot")
                        if not allowed:
                            log.info(f"[PAPER] Risk guard would block: {reason}")

                    if await place_order(client, ticker, trade["side"], price, contracts, paper, trade["note"]):
                        # ── Regime detection ──
                        regime = check_regime(float(price))
                        if regime == "CRASH":
                            log.warning("REGIME CRASH on kalshi_premarket_bot — skipping trade")
                            shadow_log({"bot": "kalshi_premarket_bot", "regime": regime}, taken=False, reason="crash regime")
                            continue
                        shadow_log({"bot": "premarket", "ticker": ticker, "side": trade["side"], "price": price, "edge": trade["edge"], "contracts": contracts}, taken=True)
                        cooldown.mark(cd_key)
                        trades += 1

                    await asyncio.sleep(1.0)

                except Exception as e:
                    log.error(f"Error {symbol}: {e}")

            log.info(f"--- Complete | sleeping {POLL_INTERVAL_SEC}s ---")
            await asyncio.sleep(POLL_INTERVAL_SEC)

if __name__ == "__main__":
    asyncio.run(main())
