"""
╔══════════════════════════════════════════════════════════════════╗
║     CYBER THREAT INTELLIGENCE PLATFORM — ITALY LIVE DASHBOARD   ║
║     Single-file FastAPI application with embedded frontend       ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    pip install fastapi uvicorn asyncpg python-dotenv
    python app.py

Environment variables (.env):
    DB_HOST=localhost
    DB_PORT=5432
    DB_NAME=cyber_intel
    DB_USER=postgres
    DB_PASSWORD=password
    POLL_INTERVAL=5
"""

import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

import uvicorn

try:
    import asyncpg
except ImportError:
    print("Missing dependency: pip install asyncpg")
    sys.exit(1)

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse
except ImportError:
    print("Missing dependency: pip install fastapi")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── CONFIG ──────────────────────────────────────────────────────────────────

DB_HOST     = os.getenv("DB_HOST", "localhost")
DB_PORT     = int(os.getenv("DB_PORT", "5432"))
DB_NAME     = os.getenv("DB_NAME", "cyber_intel")
DB_USER     = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))

# ─── DATABASE ────────────────────────────────────────────────────────────────

pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    global pool
    if pool is None:
        pool = await asyncpg.create_pool(
            host=DB_HOST, port=DB_PORT,
            database=DB_NAME, user=DB_USER,
            password=DB_PASSWORD, min_size=2, max_size=10,
        )
    return pool


def rec(r) -> dict:
    """Convert asyncpg Record to JSON-safe dict."""
    if r is None:
        return {}
    d = dict(r)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


async def db_get_events(attack_type=None, sector=None, severity=None, limit=200) -> list:
    p = await get_pool()
    conds, args, i = ["latitude IS NOT NULL", "longitude IS NOT NULL"], [], 1
    if attack_type:
        conds.append(f"attack_type ILIKE ${i}"); args.append(f"%{attack_type}%"); i += 1
    if sector:
        conds.append(f"sector ILIKE ${i}"); args.append(f"%{sector}%"); i += 1
    if severity:
        conds.append(f"severity ILIKE ${i}"); args.append(f"%{severity}%"); i += 1
    where = " AND ".join(conds)
    args.append(limit)
    rows = await p.fetch(
        f"SELECT * FROM cyber_news WHERE {where} ORDER BY created_at DESC LIMIT ${i}",
        *args
    )
    return [rec(r) for r in rows]


async def db_get_recent(limit=20) -> list:
    p = await get_pool()
    rows = await p.fetch(
        "SELECT id, title, attack_type, sector, severity, target, source, link, created_at, latitude, longitude "
        "FROM cyber_news ORDER BY created_at DESC LIMIT $1", limit
    )
    return [rec(r) for r in rows]


async def db_get_stats() -> dict:
    p = await get_pool()
    now = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week  = now - timedelta(days=7)
    month = now - timedelta(days=30)
    row = await p.fetchrow("""
        SELECT
            COUNT(*) FILTER (WHERE created_at >= $1) AS today,
            COUNT(*) FILTER (WHERE created_at >= $2) AS week,
            COUNT(*) FILTER (WHERE created_at >= $3) AS month,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
            COUNT(*) AS total
        FROM cyber_news
    """, today, week, month)
    return rec(row)


async def db_get_sectors() -> list:
    p = await get_pool()
    rows = await p.fetch("""
        SELECT sector, COUNT(*) AS count
        FROM cyber_news WHERE sector IS NOT NULL AND sector != ''
        GROUP BY sector ORDER BY count DESC LIMIT 10
    """)
    return [rec(r) for r in rows]


async def db_get_attack_types() -> list:
    p = await get_pool()
    rows = await p.fetch("""
        SELECT attack_type, COUNT(*) AS count
        FROM cyber_news WHERE attack_type IS NOT NULL AND attack_type != ''
        GROUP BY attack_type ORDER BY count DESC LIMIT 10
    """)
    return [rec(r) for r in rows]


async def db_get_timeline() -> list:
    p = await get_pool()
    rows = await p.fetch("""
        SELECT
            date_trunc('hour', created_at) AS hour,
            COUNT(*) AS count
        FROM cyber_news
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY hour ORDER BY hour
    """)
    return [rec(r) for r in rows]


async def db_get_severity_dist() -> list:
    p = await get_pool()
    rows = await p.fetch("""
        SELECT severity, COUNT(*) AS count
        FROM cyber_news WHERE severity IS NOT NULL AND severity != ''
        GROUP BY severity ORDER BY count DESC
    """)
    return [rec(r) for r in rows]


async def db_get_regions() -> list:
    p = await get_pool()
    rows = await p.fetch("""
        SELECT target AS region, COUNT(*) AS count
        FROM cyber_news
        WHERE country ILIKE '%ital%' OR country = 'IT'
        GROUP BY target ORDER BY count DESC LIMIT 15
    """)
    return [rec(r) for r in rows]


async def db_get_since(ts: datetime) -> list:
    p = await get_pool()
    rows = await p.fetch(
        "SELECT * FROM cyber_news WHERE created_at > $1 ORDER BY created_at ASC", ts
    )
    return [rec(r) for r in rows]


async def db_get_filter_options() -> dict:
    p = await get_pool()
    at = await p.fetch("SELECT DISTINCT attack_type FROM cyber_news WHERE attack_type IS NOT NULL AND attack_type!='' ORDER BY attack_type")
    se = await p.fetch("SELECT DISTINCT sector FROM cyber_news WHERE sector IS NOT NULL AND sector!='' ORDER BY sector")
    sv = await p.fetch("SELECT DISTINCT severity FROM cyber_news WHERE severity IS NOT NULL AND severity!='' ORDER BY severity")
    return {
        "attack_types": [r["attack_type"] for r in at],
        "sectors": [r["sector"] for r in se],
        "severities": [r["severity"] for r in sv],
    }

# ─── WEBSOCKET MANAGER ───────────────────────────────────────────────────────

class WSManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
        logger.info(f"WS connected [{len(self.connections)} total]")

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)
        logger.info(f"WS disconnected [{len(self.connections)} total]")

    async def broadcast(self, msg: dict):
        dead = []
        data = json.dumps(msg, default=str)
        for ws in self.connections:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = WSManager()

# ─── POLLER ──────────────────────────────────────────────────────────────────

async def poller():
    last = datetime.utcnow()
    while True:
        try:
            await asyncio.sleep(POLL_INTERVAL)
            new_events = await db_get_since(last)
            if new_events:
                logger.info(f"Detected {len(new_events)} new events")
                for ev in new_events:
                    await ws_manager.broadcast({"type": "new_event", "data": ev})
                    # Alert for critical
                    if ev.get("severity") == "critical":
                        await ws_manager.broadcast({
                            "type": "critical_alert",
                            "data": {
                                "title": ev.get("title", "Unknown"),
                                "attack_type": ev.get("attack_type", ""),
                                "target": ev.get("target", ""),
                            }
                        })

                stats = await db_get_stats()
                await ws_manager.broadcast({"type": "stats_update", "data": stats})

                sectors = await db_get_sectors()
                await ws_manager.broadcast({"type": "sector_update", "data": sectors})

                attacks = await db_get_attack_types()
                await ws_manager.broadcast({"type": "attack_type_update", "data": attacks})

                timeline = await db_get_timeline()
                await ws_manager.broadcast({"type": "timeline_update", "data": timeline})

                recent = await db_get_recent(20)
                await ws_manager.broadcast({"type": "recent_update", "data": recent})

            last = datetime.utcnow()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Poller error: {e}")
            await asyncio.sleep(5)

# ─── APP LIFECYCLE ───────────────────────────────────────────────────────────

poll_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global poll_task
    try:
        await get_pool()
        logger.info("Database connected")
    except Exception as e:
        logger.warning(f"DB connection failed (demo mode): {e}")
    poll_task = asyncio.create_task(poller())
    yield
    if poll_task:
        poll_task.cancel()
    global pool
    if pool:
        await pool.close()

app = FastAPI(title="Cyber Intel Italy", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── API ENDPOINTS ───────────────────────────────────────────────────────────

@app.get("/api/events")
async def get_events(
    attack_type: Optional[str] = None,
    sector: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(200, le=1000),
):
    events = await db_get_events(attack_type, sector, severity, limit)
    return {"events": events}

@app.get("/api/events/recent")
async def get_recent(limit: int = Query(20, le=100)):
    return {"events": await db_get_recent(limit)}

@app.get("/api/stats")
async def get_stats():
    return await db_get_stats()

@app.get("/api/charts/sectors")
async def get_sectors():
    return {"data": await db_get_sectors()}

@app.get("/api/charts/attack-types")
async def get_attack_types():
    return {"data": await db_get_attack_types()}

@app.get("/api/charts/timeline")
async def get_timeline():
    return {"data": await db_get_timeline()}

@app.get("/api/charts/severity")
async def get_severity():
    return {"data": await db_get_severity_dist()}

@app.get("/api/regions")
async def get_regions():
    return {"data": await db_get_regions()}

@app.get("/api/filters")
async def get_filters():
    return await db_get_filter_options()

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        # Send initial data bundle
        events = await db_get_events()
        await ws.send_text(json.dumps({"type": "initial_events", "data": events}, default=str))

        stats = await db_get_stats()
        await ws.send_text(json.dumps({"type": "stats_update", "data": stats}, default=str))

        sectors = await db_get_sectors()
        await ws.send_text(json.dumps({"type": "sector_update", "data": sectors}, default=str))

        attacks = await db_get_attack_types()
        await ws.send_text(json.dumps({"type": "attack_type_update", "data": attacks}, default=str))

        timeline = await db_get_timeline()
        await ws.send_text(json.dumps({"type": "timeline_update", "data": timeline}, default=str))

        recent = await db_get_recent(20)
        await ws.send_text(json.dumps({"type": "recent_update", "data": recent}, default=str))

        severity = await db_get_severity_dist()
        await ws.send_text(json.dumps({"type": "severity_update", "data": severity}, default=str))

        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception as e:
        logger.error(f"WS error: {e}")
        ws_manager.disconnect(ws)

# ─── FRONTEND HTML ───────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>CTIMAP — Italy Cyber Threat Intelligence</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
<style>
  :root {
    --bg:       #060a14;
    --surface:  #0d1321;
    --panel:    #111827;
    --border:   #1e2d45;
    --primary:  #00d4ff;
    --accent:   #1f6feb;
    --red:      #ff3b3b;
    --orange:   #ff8c00;
    --yellow:   #f0c000;
    --green:    #00e676;
    --text:     #c9d6e8;
    --muted:    #4a5568;
    --font-display: 'Syne', sans-serif;
    --font-mono:    'Share Tech Mono', monospace;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  html, body { height:100%; background:var(--bg); color:var(--text); font-family:var(--font-mono); overflow-x:hidden; }

  /* Scanline overlay */
  body::before {
    content:''; position:fixed; inset:0; pointer-events:none; z-index:9999;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.04) 2px, rgba(0,0,0,0.04) 4px);
  }

  /* Grid noise */
  body::after {
    content:''; position:fixed; inset:0; pointer-events:none; z-index:9998; opacity:0.03;
    background-image: radial-gradient(circle, #00d4ff 1px, transparent 1px);
    background-size: 40px 40px;
  }

  /* ── HEADER ── */
  header {
    display:flex; align-items:center; justify-content:space-between;
    padding:12px 24px; border-bottom:1px solid var(--border);
    background:linear-gradient(135deg, #060a14 0%, #0a1628 100%);
    position:sticky; top:0; z-index:1000;
  }
  .logo {
    display:flex; align-items:center; gap:12px;
  }
  .logo-icon {
    width:36px; height:36px; border:2px solid var(--primary);
    display:flex; align-items:center; justify-content:center;
    clip-path: polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);
    background:rgba(0,212,255,0.1); animation: pulse-border 2s ease-in-out infinite;
  }
  @keyframes pulse-border { 0%,100%{box-shadow:0 0 8px var(--primary)} 50%{box-shadow:0 0 20px var(--primary),0 0 40px rgba(0,212,255,0.3)} }
  .logo-text { font-family:var(--font-display); font-weight:800; font-size:1.3rem; letter-spacing:3px; color:#fff; }
  .logo-sub { font-size:0.65rem; color:var(--primary); letter-spacing:4px; text-transform:uppercase; }
  .header-right { display:flex; align-items:center; gap:20px; }
  .live-badge {
    display:flex; align-items:center; gap:6px; font-size:0.7rem;
    color:var(--green); letter-spacing:2px; text-transform:uppercase;
  }
  .live-dot { width:8px; height:8px; border-radius:50%; background:var(--green); animation:blink 1s ease-in-out infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
  .conn-status { font-size:0.65rem; color:var(--muted); letter-spacing:1px; }
  .time-display { font-size:0.75rem; color:var(--primary); }

  /* ── ALERT BANNER ── */
  #alert-banner {
    display:none; background:linear-gradient(90deg,rgba(255,59,59,0.15),rgba(255,59,59,0.05));
    border-bottom:1px solid var(--red); padding:10px 24px;
    font-size:0.85rem; color:var(--red); letter-spacing:1px;
    animation: slideDown 0.3s ease; position:relative;
  }
  @keyframes slideDown { from{transform:translateY(-100%);opacity:0} to{transform:translateY(0);opacity:1} }
  #alert-banner .close-alert { position:absolute; right:20px; top:50%; transform:translateY(-50%); cursor:pointer; opacity:0.7; }

  /* ── FILTERS BAR ── */
  .filters-bar {
    display:flex; gap:10px; padding:10px 24px; border-bottom:1px solid var(--border);
    background:var(--surface); flex-wrap:wrap; align-items:center;
  }
  .filters-bar label { font-size:0.65rem; color:var(--muted); letter-spacing:2px; text-transform:uppercase; margin-right:4px; }
  .filters-bar select {
    background:var(--panel); border:1px solid var(--border); color:var(--text);
    padding:5px 10px; font-family:var(--font-mono); font-size:0.72rem; border-radius:3px; cursor:pointer;
    transition: border-color 0.2s;
  }
  .filters-bar select:hover { border-color:var(--primary); }
  .btn-reset {
    margin-left:auto; background:transparent; border:1px solid var(--border);
    color:var(--muted); padding:5px 14px; font-family:var(--font-mono); font-size:0.72rem;
    cursor:pointer; border-radius:3px; transition:all 0.2s; letter-spacing:1px;
  }
  .btn-reset:hover { border-color:var(--primary); color:var(--primary); }

  /* ── MAIN GRID ── */
  .main-grid {
    display:grid;
    grid-template-columns: 1fr 380px;
    grid-template-rows: auto 1fr auto;
    gap:0;
    height:calc(100vh - 110px);
  }
  @media (max-width: 1024px) {
    .main-grid { grid-template-columns:1fr; grid-template-rows:auto; height:auto; }
  }

  /* ── STATS ROW ── */
  .stats-row {
    grid-column: 1 / -1;
    display:grid; grid-template-columns:repeat(4,1fr);
    border-bottom:1px solid var(--border);
  }
  @media(max-width:768px) { .stats-row { grid-template-columns:repeat(2,1fr); } }

  .stat-card {
    padding:20px 24px; border-right:1px solid var(--border);
    position:relative; overflow:hidden;
    transition:background 0.2s;
  }
  .stat-card:last-child { border-right:none; }
  .stat-card::before {
    content:''; position:absolute; bottom:0; left:0; right:0; height:2px;
    background:linear-gradient(90deg, transparent, var(--primary), transparent);
    transform:scaleX(0); transition:transform 0.3s;
  }
  .stat-card:hover::before { transform:scaleX(1); }
  .stat-label { font-size:0.62rem; color:var(--muted); letter-spacing:3px; text-transform:uppercase; margin-bottom:8px; }
  .stat-value { font-family:var(--font-display); font-size:2.4rem; font-weight:800; line-height:1; }
  .stat-value.today   { color:var(--primary); }
  .stat-value.week    { color:#7dd3fc; }
  .stat-value.month   { color:#93c5fd; }
  .stat-value.critical{ color:var(--red); }
  .stat-sub { font-size:0.6rem; color:var(--muted); margin-top:4px; }

  /* ── MAP PANEL ── */
  .map-panel {
    position:relative; background:var(--surface);
    border-right:1px solid var(--border);
  }
  #map {
    width:100%; height:100%;
    background:#060a14;
  }
  .map-label {
    position:absolute; top:12px; left:50%; transform:translateX(-50%);
    background:rgba(6,10,20,0.85); border:1px solid var(--border);
    padding:4px 14px; font-size:0.62rem; letter-spacing:3px; color:var(--primary);
    text-transform:uppercase; z-index:500; pointer-events:none; backdrop-filter:blur(4px);
  }
  .map-toggle {
    position:absolute; bottom:16px; left:12px; z-index:500;
    display:flex; gap:6px;
  }
  .map-toggle button {
    background:rgba(6,10,20,0.85); border:1px solid var(--border);
    color:var(--text); padding:5px 12px; font-family:var(--font-mono); font-size:0.65rem;
    cursor:pointer; letter-spacing:1px; transition:all 0.2s; backdrop-filter:blur(4px);
  }
  .map-toggle button.active { border-color:var(--primary); color:var(--primary); }
  .map-counter {
    position:absolute; top:12px; right:12px; z-index:500;
    background:rgba(6,10,20,0.85); border:1px solid var(--border);
    padding:4px 12px; font-size:0.65rem; backdrop-filter:blur(4px);
    color:var(--text);
  }

  /* ── SIDEBAR ── */
  .sidebar {
    display:grid; grid-template-rows:1fr 1fr;
    border-left:1px solid var(--border);
    overflow:hidden;
  }

  /* ── CHART PANELS ── */
  .chart-panel {
    padding:16px; border-bottom:1px solid var(--border);
    display:flex; flex-direction:column; overflow:hidden;
  }
  .panel-title {
    font-size:0.62rem; color:var(--primary); letter-spacing:3px;
    text-transform:uppercase; margin-bottom:12px;
    display:flex; align-items:center; gap:8px;
  }
  .panel-title::before {
    content:''; width:3px; height:12px; background:var(--primary);
    display:inline-block;
  }
  .chart-wrap { flex:1; position:relative; min-height:0; }

  /* ── BOTTOM ROW ── */
  .bottom-row {
    grid-column: 1 / -1;
    display:grid; grid-template-columns:1fr 380px;
    border-top:1px solid var(--border);
    max-height:280px;
  }
  @media(max-width:1024px) { .bottom-row { grid-template-columns:1fr; max-height:none; } }

  /* ── FEED ── */
  .feed-panel {
    border-right:1px solid var(--border);
    overflow-y:auto; padding:0;
  }
  .feed-header {
    padding:12px 16px; border-bottom:1px solid var(--border);
    font-size:0.62rem; color:var(--primary); letter-spacing:3px;
    text-transform:uppercase; position:sticky; top:0; background:var(--surface); z-index:10;
    display:flex; align-items:center; gap:8px;
  }
  .feed-header::before { content:''; width:3px; height:12px; background:var(--primary); display:inline-block; }
  .feed-count { margin-left:auto; color:var(--muted); }

  .feed-item {
    display:flex; align-items:flex-start; gap:12px;
    padding:10px 16px; border-bottom:1px solid rgba(30,45,69,0.5);
    cursor:pointer; transition:background 0.2s;
    animation: fadeSlide 0.4s ease;
    text-decoration:none; color:inherit;
  }
  @keyframes fadeSlide { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:translateX(0)} }
  .feed-item:hover { background:rgba(0,212,255,0.04); }
  .feed-item.new { animation: highlight 1.5s ease; }
  @keyframes highlight { 0%{background:rgba(0,212,255,0.15)} 100%{background:transparent} }

  .feed-sev {
    width:6px; min-width:6px; height:6px; border-radius:50%; margin-top:6px;
  }
  .feed-sev.critical { background:var(--red); box-shadow:0 0 6px var(--red); }
  .feed-sev.high     { background:var(--orange); box-shadow:0 0 6px var(--orange); }
  .feed-sev.medium   { background:var(--yellow); }
  .feed-sev.low      { background:var(--green); }

  .feed-body { flex:1; min-width:0; }
  .feed-title { font-size:0.75rem; color:#e2e8f0; line-height:1.3; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .feed-meta  { font-size:0.62rem; color:var(--muted); margin-top:3px; }
  .feed-tag   { display:inline-block; background:rgba(31,111,235,0.2); border:1px solid rgba(31,111,235,0.3); color:#7dd3fc; padding:1px 6px; font-size:0.58rem; letter-spacing:1px; text-transform:uppercase; margin-right:4px; }
  .feed-time  { font-size:0.58rem; color:var(--muted); white-space:nowrap; }

  /* ── TIMELINE PANEL ── */
  .timeline-panel {
    padding:16px; overflow:hidden; display:flex; flex-direction:column;
  }

  /* ── LEAFLET POPUP CUSTOM ── */
  .leaflet-popup-content-wrapper {
    background:rgba(13,19,33,0.97); border:1px solid var(--border);
    border-radius:4px; color:var(--text); font-family:var(--font-mono);
    box-shadow:0 4px 20px rgba(0,0,0,0.5), 0 0 0 1px rgba(0,212,255,0.1);
    backdrop-filter:blur(8px);
  }
  .leaflet-popup-tip { background:rgba(13,19,33,0.97); }
  .popup-title { font-family:var(--font-display); font-weight:700; font-size:0.85rem; color:#fff; margin-bottom:8px; line-height:1.3; }
  .popup-row { display:flex; gap:8px; margin-bottom:4px; font-size:0.68rem; }
  .popup-label { color:var(--muted); min-width:80px; }
  .popup-val   { color:var(--text); }
  .popup-sev   { font-weight:bold; }
  .popup-sev.critical { color:var(--red); }
  .popup-sev.high     { color:var(--orange); }
  .popup-sev.medium   { color:var(--yellow); }
  .popup-sev.low      { color:var(--green); }
  .popup-link { display:inline-block; margin-top:10px; color:var(--primary); font-size:0.68rem; text-decoration:none; border:1px solid rgba(0,212,255,0.3); padding:4px 10px; transition:all 0.2s; }
  .popup-link:hover { background:rgba(0,212,255,0.1); }
  .leaflet-popup-close-button { color:var(--muted) !important; }

  /* ── MODAL ── */
  .modal-overlay {
    display:none; position:fixed; inset:0; z-index:2000;
    background:rgba(0,0,0,0.7); backdrop-filter:blur(4px);
    align-items:center; justify-content:center;
  }
  .modal-overlay.open { display:flex; animation:fadeIn 0.2s ease; }
  @keyframes fadeIn { from{opacity:0} to{opacity:1} }
  .modal {
    background:var(--panel); border:1px solid var(--border);
    max-width:600px; width:90%; max-height:80vh; overflow-y:auto;
    box-shadow:0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(0,212,255,0.1);
    animation:scaleIn 0.2s ease;
  }
  @keyframes scaleIn { from{transform:scale(0.95);opacity:0} to{transform:scale(1);opacity:1} }
  .modal-header {
    padding:20px 24px; border-bottom:1px solid var(--border);
    display:flex; justify-content:space-between; align-items:flex-start;
    background:linear-gradient(135deg,rgba(0,212,255,0.05),transparent);
  }
  .modal-title { font-family:var(--font-display); font-size:1.1rem; font-weight:700; color:#fff; flex:1; padding-right:16px; line-height:1.3; }
  .modal-close { background:none; border:none; color:var(--muted); cursor:pointer; font-size:1.2rem; transition:color 0.2s; }
  .modal-close:hover { color:var(--red); }
  .modal-body { padding:20px 24px; }
  .modal-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
  .modal-field label { font-size:0.6rem; color:var(--muted); letter-spacing:2px; text-transform:uppercase; display:block; margin-bottom:4px; }
  .modal-field span { font-size:0.85rem; color:var(--text); }
  .modal-field.full { grid-column:1/-1; }
  .modal-link { display:inline-flex; align-items:center; gap:8px; color:var(--primary); text-decoration:none; font-size:0.8rem; border:1px solid rgba(0,212,255,0.3); padding:8px 16px; transition:all 0.2s; margin-top:4px; }
  .modal-link:hover { background:rgba(0,212,255,0.1); }
  .sev-badge { display:inline-block; padding:2px 10px; font-size:0.7rem; font-weight:bold; letter-spacing:2px; text-transform:uppercase; }
  .sev-badge.critical { background:rgba(255,59,59,0.15); border:1px solid var(--red); color:var(--red); }
  .sev-badge.high     { background:rgba(255,140,0,0.15); border:1px solid var(--orange); color:var(--orange); }
  .sev-badge.medium   { background:rgba(240,192,0,0.15); border:1px solid var(--yellow); color:var(--yellow); }
  .sev-badge.low      { background:rgba(0,230,118,0.15); border:1px solid var(--green); color:var(--green); }

  /* ── SCROLLBARS ── */
  ::-webkit-scrollbar { width:4px; }
  ::-webkit-scrollbar-track { background:var(--bg); }
  ::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
  ::-webkit-scrollbar-thumb:hover { background:var(--muted); }

  /* ── CHART.JS overrides ── */
  canvas { display:block; }

  /* ── REGION LIST ── */
  .region-list { overflow-y:auto; flex:1; }
  .region-item {
    display:flex; align-items:center; gap:10px;
    padding:6px 0; border-bottom:1px solid rgba(30,45,69,0.4);
    font-size:0.72rem;
  }
  .region-rank { color:var(--muted); width:16px; text-align:right; }
  .region-name { flex:1; color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .region-bar-wrap { width:80px; height:4px; background:rgba(30,45,69,0.8); border-radius:2px; }
  .region-bar { height:100%; background:var(--primary); border-radius:2px; transition:width 0.5s ease; }
  .region-count { color:var(--primary); width:24px; text-align:right; }
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <div>
      <div class="logo-text">CTIMAP</div>
      <div class="logo-sub">Italy Cyber Threat Intelligence</div>
    </div>
  </div>
  <div class="header-right">
    <div class="live-badge"><span class="live-dot"></span> LIVE</div>
    <div class="conn-status" id="conn-status">● CONNECTING</div>
    <div class="time-display" id="clock"></div>
  </div>
</header>

<!-- ALERT BANNER -->
<div id="alert-banner">
  <span id="alert-text"></span>
  <span class="close-alert" onclick="closeAlert()">✕</span>
</div>

<!-- FILTERS -->
<div class="filters-bar">
  <label>FILTER</label>
  <select id="f-severity" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
  </select>
  <select id="f-attack" onchange="applyFilters()">
    <option value="">All Attack Types</option>
  </select>
  <select id="f-sector" onchange="applyFilters()">
    <option value="">All Sectors</option>
  </select>
  <button class="btn-reset" onclick="resetFilters()">↺ RESET</button>
</div>

<!-- MAIN GRID -->
<div class="main-grid">

  <!-- STATS ROW -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-label">Today</div>
      <div class="stat-value today" id="stat-today">—</div>
      <div class="stat-sub">attacks detected</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">This Week</div>
      <div class="stat-value week" id="stat-week">—</div>
      <div class="stat-sub">incidents logged</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">This Month</div>
      <div class="stat-value month" id="stat-month">—</div>
      <div class="stat-sub">events tracked</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical</div>
      <div class="stat-value critical" id="stat-critical">—</div>
      <div class="stat-sub">high-priority threats</div>
    </div>
  </div>

  <!-- MAP -->
  <div class="map-panel">
    <div class="map-label">◈ LIVE THREAT MAP — ITALY</div>
    <div class="map-counter" id="map-counter">0 EVENTS</div>
    <div id="map"></div>
    <div class="map-toggle">
      <button class="active" id="btn-markers" onclick="setMapMode('markers')">MARKERS</button>
      <button id="btn-heat" onclick="setMapMode('heat')">HEATMAP</button>
    </div>
  </div>

  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="chart-panel">
      <div class="panel-title">Sector Distribution</div>
      <div class="chart-wrap"><canvas id="sectorChart"></canvas></div>
    </div>
    <div class="chart-panel" style="border-bottom:none;">
      <div class="panel-title">Attack Types</div>
      <div class="chart-wrap"><canvas id="attackChart"></canvas></div>
    </div>
  </div>

  <!-- BOTTOM ROW -->
  <div class="bottom-row">
    <!-- FEED -->
    <div class="feed-panel">
      <div class="feed-header">
        Recent Incidents
        <span class="feed-count" id="feed-count">0</span>
      </div>
      <div id="feed-list"></div>
    </div>

    <!-- TIMELINE -->
    <div class="timeline-panel">
      <div class="panel-title">Attack Timeline — 24h</div>
      <div class="chart-wrap" style="flex:1;"><canvas id="timelineChart"></canvas></div>
    </div>
  </div>

</div>

<!-- MODAL -->
<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title" id="modal-title"></div>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body">
      <div class="modal-grid">
        <div class="modal-field"><label>Severity</label><span id="modal-sev"></span></div>
        <div class="modal-field"><label>Attack Type</label><span id="modal-attack"></span></div>
        <div class="modal-field"><label>Sector</label><span id="modal-sector"></span></div>
        <div class="modal-field"><label>Target</label><span id="modal-target"></span></div>
        <div class="modal-field"><label>Source</label><span id="modal-source"></span></div>
        <div class="modal-field"><label>Date</label><span id="modal-date"></span></div>
        <div class="modal-field"><label>Threat Actor</label><span id="modal-actor"></span></div>
        <div class="modal-field"><label>Admiralty Code</label><span id="modal-adm"></span></div>
        <div class="modal-field full"><label>Location</label><span id="modal-loc"></span></div>
      </div>
      <a class="modal-link" id="modal-link" href="#" target="_blank" rel="noopener">↗ Read Full Article</a>
    </div>
  </div>
</div>

<script>
// ══════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════
const state = {
  events: [],
  filters: { severity:'', attack_type:'', sector:'' },
  mapMode: 'markers',
  sectorChart: null,
  attackChart: null,
  timelineChart: null,
  markers: [],
  heatLayer: null,
  markerLayer: null,
};

// ══════════════════════════════════════════════════
// CLOCK
// ══════════════════════════════════════════════════
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toUTCString().replace(' GMT','') + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ══════════════════════════════════════════════════
// MAP INIT
// ══════════════════════════════════════════════════
const map = L.map('map', {
  center: [42.5, 12.5],
  zoom: 6,
  zoomControl: true,
  attributionControl: false,
});

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  maxZoom: 19,
}).addTo(map);

state.markerLayer = L.layerGroup().addTo(map);

function severityColor(s) {
  switch((s||'').toLowerCase()) {
    case 'critical': return '#ff3b3b';
    case 'high':     return '#ff8c00';
    case 'medium':   return '#f0c000';
    case 'low':      return '#00e676';
    default:         return '#7dd3fc';
  }
}

function makeIcon(severity) {
  const color = severityColor(severity);
  const pulse = severity === 'critical' ? `
    <circle cx="12" cy="12" r="8" fill="${color}" opacity="0.2">
      <animate attributeName="r" from="8" to="14" dur="1.5s" repeatCount="indefinite"/>
      <animate attributeName="opacity" from="0.3" to="0" dur="1.5s" repeatCount="indefinite"/>
    </circle>` : '';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
    ${pulse}
    <circle cx="12" cy="12" r="6" fill="${color}" stroke="rgba(255,255,255,0.3)" stroke-width="1.5"/>
    <circle cx="12" cy="12" r="2.5" fill="white" opacity="0.8"/>
  </svg>`;
  return L.divIcon({
    className: '',
    html: svg,
    iconSize: [24, 24],
    iconAnchor: [12, 12],
    popupAnchor: [0, -14],
  });
}

function formatDate(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

function addMarker(ev) {
  if (!ev.latitude || !ev.longitude) return null;
  const lat = parseFloat(ev.latitude);
  const lng = parseFloat(ev.longitude);
  if (isNaN(lat) || isNaN(lng)) return null;

  const sev = (ev.severity||'').toLowerCase();
  const color = severityColor(sev);
  const popup = `
    <div class="popup-title">${escHtml(ev.title||'Unknown Incident')}</div>
    <div class="popup-row"><span class="popup-label">Attack Type</span><span class="popup-val">${escHtml(ev.attack_type||'—')}</span></div>
    <div class="popup-row"><span class="popup-label">Sector</span><span class="popup-val">${escHtml(ev.sector||'—')}</span></div>
    <div class="popup-row"><span class="popup-label">Severity</span><span class="popup-val popup-sev ${sev}">${sev.toUpperCase()}</span></div>
    <div class="popup-row"><span class="popup-label">Target</span><span class="popup-val">${escHtml(ev.target||'—')}</span></div>
    <div class="popup-row"><span class="popup-label">Date</span><span class="popup-val">${formatDate(ev.created_at)}</span></div>
    <div class="popup-row"><span class="popup-label">Source</span><span class="popup-val">${escHtml(ev.source||'—')}</span></div>
    ${ev.link ? `<a class="popup-link" href="${ev.link}" target="_blank" rel="noopener">↗ Read More</a>` : ''}
    <br/><a class="popup-link" style="margin-top:6px;border-color:rgba(255,255,255,0.2);color:#94a3b8;" href="#" onclick="openModal(${JSON.stringify(ev).replace(/"/g,'&quot;')});return false;">⊕ Full Details</a>
  `;

  const marker = L.marker([lat, lng], { icon: makeIcon(sev) });
  marker.bindPopup(popup, { maxWidth: 300, className: '' });
  marker.on('click', () => {});
  state.markerLayer.addLayer(marker);
  return marker;
}

function rebuildMap() {
  state.markerLayer.clearLayers();
  if (state.heatLayer) { map.removeLayer(state.heatLayer); state.heatLayer = null; }

  const filtered = getFiltered();
  document.getElementById('map-counter').textContent = filtered.length + ' EVENTS';

  if (state.mapMode === 'heat') {
    const heatData = filtered
      .filter(e => e.latitude && e.longitude)
      .map(e => [parseFloat(e.latitude), parseFloat(e.longitude), 0.7]);
    if (window.L.heatLayer) {
      state.heatLayer = L.heatLayer(heatData, { radius:35, blur:20, maxZoom:10, gradient:{0.4:'blue',0.6:'cyan',0.8:'yellow',1.0:'red'} }).addTo(map);
    }
  } else {
    filtered.forEach(ev => addMarker(ev));
  }
}

function setMapMode(mode) {
  state.mapMode = mode;
  document.getElementById('btn-markers').classList.toggle('active', mode==='markers');
  document.getElementById('btn-heat').classList.toggle('active', mode==='heat');
  rebuildMap();
}

// ══════════════════════════════════════════════════
// CHARTS
// ══════════════════════════════════════════════════
const CHART_DEFAULTS = {
  color: '#c9d6e8',
  plugins: { legend: { display: false }, tooltip: {
    backgroundColor: 'rgba(13,19,33,0.95)',
    borderColor: '#1e2d45', borderWidth: 1,
    titleFont: { family: "'Share Tech Mono'" },
    bodyFont: { family: "'Share Tech Mono'" },
    titleColor: '#e2e8f0', bodyColor: '#94a3b8',
    padding: 10,
  }},
};

function buildSectorChart() {
  const ctx = document.getElementById('sectorChart').getContext('2d');
  const gradient = ctx.createLinearGradient(0,0,0,200);
  gradient.addColorStop(0,'rgba(0,212,255,0.8)');
  gradient.addColorStop(1,'rgba(31,111,235,0.3)');
  state.sectorChart = new Chart(ctx, {
    type:'bar',
    data:{ labels:[], datasets:[{ data:[], backgroundColor: gradient, borderColor:'rgba(0,212,255,0.6)', borderWidth:1, borderRadius:2 }]},
    options:{
      responsive:true, maintainAspectRatio:false,
      indexAxis:'y',
      scales:{
        x:{ grid:{ color:'rgba(30,45,69,0.5)' }, ticks:{ color:'#4a5568', font:{family:"'Share Tech Mono'",size:10} }},
        y:{ grid:{ display:false }, ticks:{ color:'#94a3b8', font:{family:"'Share Tech Mono'",size:10} }},
      },
      ...CHART_DEFAULTS,
    }
  });
}

function buildAttackChart() {
  const ctx = document.getElementById('attackChart').getContext('2d');
  const colors = ['#ff3b3b','#ff8c00','#f0c000','#00e676','#00d4ff','#7c3aed','#ec4899'];
  state.attackChart = new Chart(ctx, {
    type:'doughnut',
    data:{ labels:[], datasets:[{ data:[], backgroundColor: colors, borderColor:'rgba(6,10,20,0.8)', borderWidth:2, hoverOffset:4 }]},
    options:{
      responsive:true, maintainAspectRatio:false, cutout:'65%',
      plugins:{
        legend:{ display:true, position:'right', labels:{ color:'#94a3b8', font:{family:"'Share Tech Mono'",size:9}, padding:8, boxWidth:10 }},
        ...CHART_DEFAULTS.plugins,
      }
    }
  });
}

function buildTimelineChart() {
  const ctx = document.getElementById('timelineChart').getContext('2d');
  const gradient = ctx.createLinearGradient(0,0,0,150);
  gradient.addColorStop(0,'rgba(0,212,255,0.3)');
  gradient.addColorStop(1,'rgba(0,212,255,0)');
  state.timelineChart = new Chart(ctx, {
    type:'line',
    data:{ labels:[], datasets:[{
      label:'Attacks', data:[],
      borderColor:'#00d4ff', backgroundColor: gradient,
      borderWidth:1.5, fill:true, tension:0.4,
      pointRadius:2, pointBackgroundColor:'#00d4ff',
    }]},
    options:{
      responsive:true, maintainAspectRatio:false,
      scales:{
        x:{ grid:{ color:'rgba(30,45,69,0.5)' }, ticks:{ color:'#4a5568', font:{family:"'Share Tech Mono'",size:9}, maxTicksLimit:8 }},
        y:{ grid:{ color:'rgba(30,45,69,0.3)' }, ticks:{ color:'#4a5568', font:{family:"'Share Tech Mono'",size:9} }, beginAtZero:true },
      },
      ...CHART_DEFAULTS,
      plugins:{...CHART_DEFAULTS.plugins, legend:{display:false}},
    }
  });
}

function updateSectorChart(data) {
  if (!state.sectorChart) return;
  state.sectorChart.data.labels = data.map(d=>capitalize(d.sector));
  state.sectorChart.data.datasets[0].data = data.map(d=>d.count);
  state.sectorChart.update('none');
}

function updateAttackChart(data) {
  if (!state.attackChart) return;
  state.attackChart.data.labels = data.map(d=>capitalize(d.attack_type));
  state.attackChart.data.datasets[0].data = data.map(d=>d.count);
  state.attackChart.update('none');
}

function updateTimelineChart(data) {
  if (!state.timelineChart) return;
  state.timelineChart.data.labels = data.map(d=>{
    const h = new Date(d.hour);
    return h.getHours().toString().padStart(2,'0')+':00';
  });
  state.timelineChart.data.datasets[0].data = data.map(d=>d.count);
  state.timelineChart.update('none');
}

// ══════════════════════════════════════════════════
// STATS
// ══════════════════════════════════════════════════
function updateStats(s) {
  animateNum('stat-today',    s.today    || 0);
  animateNum('stat-week',     s.week     || 0);
  animateNum('stat-month',    s.month    || 0);
  animateNum('stat-critical', s.critical || 0);
}

function animateNum(id, target) {
  const el = document.getElementById(id);
  const start = parseInt(el.textContent) || 0;
  const diff = target - start;
  if (diff === 0) return;
  const steps = 20, dur = 400;
  let i = 0;
  const timer = setInterval(() => {
    i++;
    el.textContent = Math.round(start + diff * (i/steps));
    if (i >= steps) { el.textContent = target; clearInterval(timer); }
  }, dur/steps);
}

// ══════════════════════════════════════════════════
// FEED
// ══════════════════════════════════════════════════
function buildFeed(events) {
  const list = document.getElementById('feed-list');
  list.innerHTML = '';
  document.getElementById('feed-count').textContent = events.length;
  events.slice(0, 50).forEach(ev => appendFeedItem(ev, false));
}

function appendFeedItem(ev, isNew = true) {
  const list = document.getElementById('feed-list');
  const sev = (ev.severity||'low').toLowerCase();
  const item = document.createElement('div');
  item.className = 'feed-item' + (isNew ? ' new' : '');
  if (ev.link) item.onclick = () => window.open(ev.link, '_blank');
  else item.onclick = () => openModal(ev);
  item.innerHTML = `
    <div class="feed-sev ${sev}"></div>
    <div class="feed-body">
      <div class="feed-title">${escHtml(ev.title||'Unknown Incident')}</div>
      <div class="feed-meta">
        <span class="feed-tag">${escHtml(ev.attack_type||'?')}</span>
        <span class="feed-tag" style="border-color:rgba(124,58,237,0.3);color:#a78bfa;background:rgba(124,58,237,0.1);">${escHtml(ev.sector||'?')}</span>
        ${ev.target ? `<span style="color:#64748b;font-size:0.6rem;">→ ${escHtml(ev.target)}</span>` : ''}
      </div>
    </div>
    <div class="feed-time">${timeAgo(ev.created_at)}</div>
  `;
  if (isNew) {
    list.insertBefore(item, list.firstChild);
    const count = parseInt(document.getElementById('feed-count').textContent) || 0;
    document.getElementById('feed-count').textContent = count + 1;
  } else {
    list.appendChild(item);
  }
}

function timeAgo(ts) {
  if (!ts) return '';
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff/60000);
  if (m < 1) return 'now';
  if (m < 60) return m+'m';
  const h = Math.floor(m/60);
  if (h < 24) return h+'h';
  return Math.floor(h/24)+'d';
}

// ══════════════════════════════════════════════════
// FILTERS
// ══════════════════════════════════════════════════
function getFiltered() {
  const { severity, attack_type, sector } = state.filters;
  return state.events.filter(ev => {
    if (severity   && (ev.severity   ||'').toLowerCase() !== severity.toLowerCase())   return false;
    if (attack_type && (ev.attack_type||'').toLowerCase().indexOf(attack_type.toLowerCase()) < 0) return false;
    if (sector     && (ev.sector     ||'').toLowerCase().indexOf(sector.toLowerCase())   < 0) return false;
    return true;
  });
}

function applyFilters() {
  state.filters.severity   = document.getElementById('f-severity').value;
  state.filters.attack_type= document.getElementById('f-attack').value;
  state.filters.sector     = document.getElementById('f-sector').value;
  rebuildMap();
}

function resetFilters() {
  document.getElementById('f-severity').value = '';
  document.getElementById('f-attack').value   = '';
  document.getElementById('f-sector').value   = '';
  state.filters = { severity:'', attack_type:'', sector:'' };
  rebuildMap();
}

function populateFilters(options) {
  const atSel = document.getElementById('f-attack');
  const seSel = document.getElementById('f-sector');
  options.attack_types.forEach(at => {
    const o = document.createElement('option'); o.value=at; o.textContent=capitalize(at);
    atSel.appendChild(o);
  });
  options.sectors.forEach(s => {
    const o = document.createElement('option'); o.value=s; o.textContent=capitalize(s);
    seSel.appendChild(o);
  });
}

// ══════════════════════════════════════════════════
// MODAL
// ══════════════════════════════════════════════════
function openModal(ev) {
  document.getElementById('modal-title').textContent  = ev.title || 'Unknown Incident';
  const sev = (ev.severity||'').toLowerCase();
  document.getElementById('modal-sev').innerHTML = `<span class="sev-badge ${sev}">${sev.toUpperCase()||'—'}</span>`;
  document.getElementById('modal-attack').textContent  = capitalize(ev.attack_type||'—');
  document.getElementById('modal-sector').textContent  = capitalize(ev.sector||'—');
  document.getElementById('modal-target').textContent  = ev.target||'—';
  document.getElementById('modal-source').textContent  = ev.source||'—';
  document.getElementById('modal-date').textContent    = formatDate(ev.created_at);
  document.getElementById('modal-actor').textContent   = ev.threat_actor||'—';
  document.getElementById('modal-adm').textContent     = ev.admiralty_code||'—';
  document.getElementById('modal-loc').textContent     = [ev.latitude, ev.longitude].filter(Boolean).join(', ') || '—';
  const link = document.getElementById('modal-link');
  if (ev.link) { link.href=ev.link; link.style.display='inline-flex'; }
  else link.style.display='none';
  document.getElementById('modal').classList.add('open');
}

function closeModal() {
  document.getElementById('modal').classList.remove('open');
}

document.addEventListener('keydown', e => { if (e.key==='Escape') closeModal(); });

// ══════════════════════════════════════════════════
// ALERT BANNER
// ══════════════════════════════════════════════════
let alertTimer;
function showAlert(text) {
  const banner = document.getElementById('alert-banner');
  document.getElementById('alert-text').textContent = '⚠  ' + text;
  banner.style.display = 'block';
  clearTimeout(alertTimer);
  alertTimer = setTimeout(closeAlert, 10000);
}
function closeAlert() {
  document.getElementById('alert-banner').style.display = 'none';
}

// ══════════════════════════════════════════════════
// WEBSOCKET
// ══════════════════════════════════════════════════
let ws, reconnectDelay = 2000;

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    document.getElementById('conn-status').textContent = '● CONNECTED';
    document.getElementById('conn-status').style.color = '#00e676';
    reconnectDelay = 2000;
  };

  ws.onclose = () => {
    document.getElementById('conn-status').textContent = '● RECONNECTING';
    document.getElementById('conn-status').style.color = '#f0c000';
    setTimeout(connect, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.5, 30000);
  };

  ws.onerror = () => {
    document.getElementById('conn-status').textContent = '● DISCONNECTED';
    document.getElementById('conn-status').style.color = '#ff3b3b';
  };

  ws.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }

    switch(msg.type) {
      case 'initial_events':
        state.events = msg.data || [];
        rebuildMap();
        break;

      case 'new_event':
        state.events.unshift(msg.data);
        addMarker(msg.data);
        appendFeedItem(msg.data, true);
        document.getElementById('map-counter').textContent = getFiltered().length + ' EVENTS';
        break;

      case 'critical_alert':
        const d = msg.data;
        showAlert(`CRITICAL ${(d.attack_type||'ATTACK').toUpperCase()} detected — ${d.target||d.title}`);
        break;

      case 'stats_update':
        updateStats(msg.data);
        break;

      case 'sector_update':
        updateSectorChart(msg.data);
        break;

      case 'attack_type_update':
        updateAttackChart(msg.data);
        break;

      case 'timeline_update':
        updateTimelineChart(msg.data);
        break;

      case 'recent_update':
        buildFeed(msg.data);
        break;

      case 'severity_update':
        // Could add severity chart here
        break;
    }
  };
}

// ══════════════════════════════════════════════════
// UTILS
// ══════════════════════════════════════════════════
function escHtml(s) {
  if (!s) return '';
  return s.toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function capitalize(s) {
  if (!s) return '';
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ══════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
  buildSectorChart();
  buildAttackChart();
  buildTimelineChart();

  // Load filter options
  try {
    const r = await fetch('/api/filters');
    if (r.ok) populateFilters(await r.json());
  } catch {}

  connect();
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main dashboard."""
    return HTMLResponse(content=HTML)


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║   CYBER THREAT INTELLIGENCE PLATFORM — ITALY                ║
╠══════════════════════════════════════════════════════════════╣
║  Starting server...                                          ║
║  Dashboard: http://localhost:8000                            ║
║  API Docs:  http://localhost:8000/docs                       ║
╠══════════════════════════════════════════════════════════════╣
║  Required env vars (.env file or environment):               ║
║    DB_HOST     = localhost                                    ║
║    DB_PORT     = 5432                                        ║
║    DB_NAME     = cyber_intel                                 ║
║    DB_USER     = postgres                                     ║
║    DB_PASSWORD = your_password                               ║
║    POLL_INTERVAL = 5  (seconds)                              ║
╚══════════════════════════════════════════════════════════════╝
""")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
