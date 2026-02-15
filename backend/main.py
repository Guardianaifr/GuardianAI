from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import secrets
import time
import logging
import sqlite3
import datetime
from typing import List, Dict, Any
import json

import os

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardian_backend")

# Configuration (Env Vars -> Defaults)
ADMIN_USER = os.getenv("GUARDIAN_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("GUARDIAN_ADMIN_PASS", "guardian2026") # Simple default for local demo

if ADMIN_PASS == "guardian2026":
    logger.warning("⚠️  USING DEFAULT PASSWORD! Set GUARDIAN_ADMIN_PASS environment variable for production.")

app = FastAPI(title="GuardianAI Backend v1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "guardian.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id TEXT,
        event_type TEXT,
        severity TEXT,
        details TEXT,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT,
        latency_ms REAL,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id TEXT,
        action TEXT,
        user TEXT,
        details TEXT,
        timestamp REAL,
        signature TEXT -- Cryptographic proof (simulated)
    )
    """)
    conn.commit()
    conn.close()
    logger.info(f"SQLite DB initialized at {DB_PATH}")

init_db()

class SecurityEvent(BaseModel):
    guardian_id: str
    event_type: str
    severity: str
    details: dict
    timestamp: float = 0.0

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# Security / Auth
security = HTTPBasic()

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    # Default Credentials - CHANGE IN PRODUCTION
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USER)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASS)
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

async def send_webhook_alert(event: SecurityEvent):
    # Broadcast to Dashboard via WebSocket
    message = json.dumps({
        "type": "new_event",
        "data": {
            "guardian_id": event.guardian_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "details": event.details,
            "timestamp": event.timestamp
        }
    })
    await manager.broadcast(message)

@app.post("/api/v1/telemetry")
async def ingest_telemetry(event: SecurityEvent):
    if event.timestamp == 0.0:
        event.timestamp = time.time()
        
    logger.info(f"Ingesting {event.event_type} from {event.guardian_id}")
    
    # Normalize severity
    event.severity = event.severity.upper()
    
    # 1. Persist to SQLite
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Insert new event
    cur.execute(
        "INSERT INTO security_events (guardian_id, event_type, severity, details, timestamp) VALUES (?, ?, ?, ?, ?)",
        (event.guardian_id, event.event_type, event.severity, json.dumps(event.details), event.timestamp)
    )

    # 2. Immutable Audit Log (Critical Events)
    if event.event_type == "admin_action":
        import hashlib
        # Simulate cryptographic signing of the log entry
        payload = f"{event.guardian_id}:{event.timestamp}:{json.dumps(event.details)}"
        signature = hashlib.sha256(payload.encode()).hexdigest()
        
        cur.execute(
            "INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature) VALUES (?, ?, ?, ?, ?, ?)",
            (event.guardian_id, event.details.get("action", "unknown"), event.details.get("user", "unknown"), json.dumps(event.details), event.timestamp, signature)
        )


    # Extract Analytics if present (Add to analytics table)
    if "latency_ms" in event.details and "path" in event.details:
        try:
            latency = float(event.details["latency_ms"].replace("ms", ""))
            path = event.details["path"]
            cur.execute(
                "INSERT INTO analytics (path, latency_ms, timestamp) VALUES (?, ?, ?)",
                (path, latency, event.timestamp)
            )
        except:
            pass
    
    # 2. Retention Policy: Auto-purge events older than 30 days
    retention_cutoff = time.time() - (30 * 24 * 60 * 60)
    cur.execute("DELETE FROM security_events WHERE timestamp < ?", (retention_cutoff,))
    
    conn.commit()
    conn.close()

    # 3. Fire Webhook Alert
    await send_webhook_alert(event)
    
    return {"status": "persisted", "event_id": event.guardian_id}

from fastapi.responses import StreamingResponse
import io
import csv
import threading

@app.get("/api/v1/export/json")
async def export_json(username: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    
    data = [
        {
            "id": r[0], "guardian_id": r[1], "event_type": r[2], 
            "severity": r[3], "details": json.loads(r[4]), "timestamp": r[5]
        } for r in rows
    ]
    return data

@app.get("/api/v1/analytics")
async def get_analytics(username: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Total Analytics
    cur.execute("SELECT COUNT(*), AVG(latency_ms) FROM analytics")
    total_count, avg_latency = cur.fetchone()

    # Total Blocked (Lifetime)
    cur.execute("SELECT COUNT(*) FROM security_events WHERE severity IN ('HIGH', 'CRITICAL')")
    total_blocked = cur.fetchone()[0]
    
    # Path Breakdown
    cur.execute("SELECT path, COUNT(*) FROM analytics GROUP BY path")
    paths = dict(cur.fetchall())
    
    conn.close()
    
    return {
        "total_requests": total_count or 0,
        "total_blocked": total_blocked or 0,
        "avg_latency_ms": round(avg_latency or 0, 2),
        "path_breakdown": paths,
        "fast_path_pct": round((sum(v for k,v in paths.items() if 'fast' in k) / total_count * 100) if total_count else 0, 1)
    }

@app.get("/api/v1/export/csv")
async def export_csv(username: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "GuardianID", "EventType", "Severity", "Details", "Timestamp"])
    for r in rows:
        writer.writerow([r[0], r[1], r[2], r[3], r[4], datetime.datetime.fromtimestamp(r[5]).isoformat()])
    
    output.seek(0)
    return StreamingResponse(
        output, 
        media_type="text/csv", 
        headers={"Content-Disposition": "attachment; filename=guardian_audit_log.csv"}
    )

@app.get("/", response_class=HTMLResponse)
async def dashboard(username: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 30")
    events = cur.fetchall()
    conn.close()
    
    # Try to read config for mode visibility
    try:
        import yaml
        with open("../guardian/config/config.yaml", 'r') as f:
            config = yaml.safe_load(f)
            sec_mode = config.get('security_policies', {}).get('security_mode', 'Balanced')
            prev_strat = config.get('security_policies', {}).get('leak_prevention_strategy', 'Redact')
    except:
        sec_mode = "Balanced"
        prev_strat = "Redact"

    return f"""
    <html>
        <head>
            <title>GuardianAI // SOC TERMINAL</title>
            <script src="https://unpkg.com/lucide@latest"></script>
            <style>
                :root {{
                    --bg-color: #050505;
                    --card-bg: #0a0a0a;
                    --text-main: #00ff41;
                    --text-dim: #008F11;
                    --accent-red: #ff003c;
                    --accent-cyan: #00e5ff;
                    --accent-yellow: #fcee0a;
                    --border-color: #1a1a1a;
                }}
                body {{ 
                    font-family: 'Courier New', Courier, monospace; 
                    background-color: var(--bg-color); 
                    color: var(--text-main); 
                    margin: 0; 
                    padding: 20px; 
                    background-image: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
                    background-size: 100% 2px, 3px 100%;
                }}
                h1 {{ 
                    color: var(--accent-cyan); 
                    margin: 0; 
                    font-size: 1.5rem; 
                    text-transform: uppercase; 
                    letter-spacing: 2px;
                    text-shadow: 0 0 5px var(--accent-cyan);
                }}
                .container {{ max-width: 1200px; margin: auto; }}
                
                /* CRT Scanline Effect */
                .scanline {{
                    width: 100%;
                    height: 100px;
                    z-index: 10;
                    background: linear-gradient(0deg, rgba(0,0,0,0) 0%, rgba(255, 255, 255, 0.04) 50%, rgba(0,0,0,0) 100%);
                    opacity: 0.1;
                    position: absolute;
                    bottom: 100%;
                    animation: scanline 10s linear infinite;
                    pointer-events: none;
                }}
                @keyframes scanline {{
                    0% {{ bottom: 100%; }}
                    100% {{ bottom: -100%; }}
                }}

                .event-card {{ 
                    background: var(--card-bg); 
                    border: 1px solid var(--text-dim); 
                    padding: 15px; 
                    margin-bottom: 15px; 
                    border-left: 4px solid var(--accent-red); 
                    position: relative; 
                    box-shadow: 0 0 10px rgba(0, 255, 65, 0.05);
                }}
                .event-card:hover {{ 
                    box-shadow: 0 0 15px rgba(0, 255, 65, 0.2); 
                    border-color: var(--text-main);
                }}
                .event-card.low, .event-card.info {{ border-left-color: var(--text-main); }} 
                .event-card.medium {{ border-left-color: var(--accent-yellow); }}
                .event-card.high {{ border-left-color: var(--accent-red); }}
                .event-card.critical {{ border-left-color: var(--accent-red); animation: pulse-red 2s infinite; }}

                @keyframes pulse-red {{
                    0% {{ box-shadow: 0 0 0 0 rgba(255, 0, 60, 0.4); }}
                    70% {{ box-shadow: 0 0 0 10px rgba(255, 0, 60, 0); }}
                    100% {{ box-shadow: 0 0 0 0 rgba(255, 0, 60, 0); }}
                }}
                
                .header-flex {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px dashed var(--text-dim); padding-bottom: 15px; }}
                .severity {{ text-transform: uppercase; font-weight: 800; font-size: 0.75rem; letter-spacing: 0.1em; }}
                .timestamp {{ color: var(--text-dim); font-size: 0.85rem; }}
                .details {{ 
                    background: #000; 
                    padding: 15px; 
                    border: 1px dashed var(--text-dim); 
                    font-family: 'Courier New', monospace; 
                    margin-top: 15px; 
                    color: #ddd; 
                    font-size: 0.85rem; 
                    line-height: 1.5; 
                    overflow-x: auto; 
                }}
                .badge {{ 
                    background: #000; 
                    padding: 4px 12px; 
                    border: 1px solid var(--text-dim); 
                    font-size: 0.7rem; 
                    font-weight: 600; 
                    text-transform: uppercase; 
                    color: var(--text-main);
                }}
                .stat-card {{ 
                    background: var(--card-bg); 
                    border: 1px solid var(--text-dim); 
                    padding: 20px; 
                    text-align: center; 
                    position: relative;
                }}
                .stat-card:before {{
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0; bottom: 0;
                    border: 1px solid transparent;
                    border-bottom-color: var(--text-main);
                }}
                .footnote {{ font-size: 0.65rem; color: var(--text-dim); margin-top: 8px; text-transform: uppercase; }}
                
                .mode-banner {{ 
                    background: #000; 
                    border: 1px solid var(--text-dim); 
                    padding: 10px 20px; 
                    margin-bottom: 25px; 
                    display: flex; 
                    align-items: center; 
                    gap: 20px; 
                }}
                
                .toast {{ 
                    position: fixed; bottom: 20px; right: 20px; 
                    background: #000; color: var(--text-main); border: 1px solid var(--text-main);
                    padding: 12px 24px; font-weight: 600; display: none; 
                    box-shadow: 0 0 10px var(--text-main);
                    z-index: 1000; 
                }}

                .snippet-diff {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; font-size: 0.8rem; }}
                .snippet-box {{ 
                    background: #000; 
                    padding: 10px; 
                    border: 1px dashed var(--text-dim); 
                }}
                
                /* Timings */
                .timings-bar {{ display: flex; height: 4px; overflow: hidden; margin-top: 10px; background: #111; border: 1px solid #333; }}
                .timing-seg {{ height: 100%; }}
                .timing-legend {{ display: flex; gap: 10px; font-size: 0.7rem; color: var(--text-dim); margin-top: 4px; flex-wrap: wrap; }}
                .timing-dot {{ width: 6px; height: 6px; display: inline-block; margin-right: 4px; }}
            </style>
        </head>
        <body>
            <div class="scanline"></div>
            <div id="toast" class="toast"></div>
            <div class="container">
                <div class="header-flex">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <i data-lucide="shield-check" style="width: 32px; height: 32px; color: var(--text-main);"></i>
                        <div>
                            <h1>GUARDIAN.AI // SOC</h1>
                            <div style="font-size: 0.7rem; color: var(--text-dim); letter-spacing: 1px;">SYSTEM STATUS: ONLINE</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button onclick="triggerExport('json')" class="badge" style="cursor:pointer; color: var(--accent-cyan); border-color: var(--accent-cyan);">[ EXPORT JSON ]</button>
                        <span class="badge" style="color: var(--accent-yellow); border-color: var(--accent-yellow);">V2.0 SECURE</span>
                    </div>
                </div>

                <!-- Security Warning (Hidden for Demo) -->
                <div style="background: rgba(255, 0, 60, 0.1); border: 1px solid var(--accent-red); padding: 10px; margin-bottom: 20px; text-align: center; color: var(--accent-red); font-weight: bold; font-size: 0.8rem; display: none;">
                    ⚠️ WARNING: You are using default credentials. Set GUARDIAN_ADMIN_PASS environment variable immediately.
                </div>

                <div class="mode-banner">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i data-lucide="settings-2" style="width: 18px; height: 18px; color: var(--text-dim);"></i>
                        <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase;">Security Mode:</span>
                        <span class="badge" style="color: var(--accent-cyan); border-color: var(--accent-cyan);">{sec_mode.upper()}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i data-lucide="shield" style="width: 18px; height: 18px; color: var(--text-dim);"></i>
                        <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase;">Privacy Strategy:</span>
                        <span class="badge" style="color: var(--accent-yellow); border-color: var(--accent-yellow);">{prev_strat.upper()}</span>
                    </div>
                    <div style="margin-left: auto; display: flex; align-items: center; gap: 8px;">
                         <i data-lucide="bar-chart-2" style="width: 18px; height: 18px; color: var(--text-dim);"></i>
                         <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase;">BLOCK RATE:</span>
                         <span id="block-rate" class="badge" style="color: var(--accent-red); border-color: var(--accent-red);">0%</span>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px;">
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Total Ingress</div>
                        <div id="stat-total" style="font-size: 2rem; font-weight: 800; color: var(--text-main); text-shadow: 0 0 5px var(--text-main);">0</div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Avg Latency</div>
                        <div id="stat-latency" style="font-size: 2rem; font-weight: 800; color: var(--accent-cyan); text-shadow: 0 0 5px var(--accent-cyan);">0ms</div>
                        <div class="footnote">INCLUDES SIMULATION OVERHEAD<br>(Prod p95 ~30ms)</div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Fast-Path</div>
                        <div id="stat-fastpath" style="font-size: 2rem; font-weight: 800; color: var(--accent-yellow); text-shadow: 0 0 5px var(--accent-yellow);">0</div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Threats Blocked</div>
                        <div id="stat-blocked" style="font-size: 2rem; font-weight: 800; color: var(--accent-red); text-shadow: 0 0 5px var(--accent-red);">0</div>
                    </div>
                </div>

                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px; border-bottom: 1px dashed var(--text-dim); padding-bottom: 10px;">
                    <i data-lucide="file-lock" style="width: 20px; height: 20px; color: var(--accent-cyan);"></i>
                    <h2 style="font-size: 1.1rem; font-weight: 600; margin: 0; text-transform: uppercase; color: #fff;">Immutable Audit Log</h2>
                </div>
                <div id="audit-log" style="margin-bottom: 40px;"></div>

                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px; border-bottom: 1px dashed var(--text-dim); padding-bottom: 10px;">
                    <i data-lucide="activity" style="width: 20px; height: 20px; color: var(--accent-red);"></i>
                    <h2 style="font-size: 1.1rem; font-weight: 600; margin: 0; text-transform: uppercase; color: #fff;">Live Threat Telemetry</h2>
                </div>
                
                <div id="events"></div>
            </div>
            <script>
                // Auto-inject credentials for dashboard API calls (this is a local tool)
                const auth = 'Basic ' + btoa('{ADMIN_USER}:{ADMIN_PASS}');

                function showToast(msg) {{
                    const t = document.getElementById('toast');
                    t.innerText = msg;
                    t.style.display = 'block';
                    setTimeout(() => t.style.display = 'none', 3000);
                }}

                function triggerExport(type) {{
                    window.location.href = `/api/v1/export/${{type}}`;
                    showToast(`Exported events as guardianai_telemetry_${{new Date().toISOString().split('T')[0]}}.${{type}}`);
                }}

                function getIcon(entity) {{
                    const e = entity.toUpperCase();
                    if (e.includes('KEY') || e.includes('TOKEN') || e.includes('SECRET')) return 'lock';
                    if (e.includes('EMAIL')) return 'mail';
                    if (e.includes('PHONE')) return 'phone';
                    return 'alert-circle';
                }}
                
                function timeAgo(timestamp) {{
                    const seconds = Math.floor((new Date() - new Date(timestamp * 1000)) / 1000);
                    let interval = seconds / 60;
                    if (interval > 1) return Math.floor(interval) + "m ago";
                    return Math.floor(seconds) + "s ago";
                }}

                async function updateStats() {{
                    try {{
                        const res = await fetch('/api/v1/analytics', {{ headers: {{ 'Authorization': auth }} }});
                        const data = await res.json();
                        document.getElementById('stat-total').innerText = data.total_requests;
                        document.getElementById('stat-blocked').innerText = data.total_blocked;
                        document.getElementById('stat-latency').innerText = data.avg_latency_ms + 'ms';
                        
                        const fastHits = (data.path_breakdown.fast_path_keyword || 0) + 
                                         (data.path_breakdown.fast_path_threat_feed || 0) + 
                                         (data.path_breakdown.fast_path_allowlist || 0) +
                                         (data.path_breakdown.base64_filter || 0);
                        document.getElementById('stat-fastpath').innerText = fastHits;
                    }} catch (e) {{ console.error("Analytics fetch failed", e); }}
                }}

                async function updateEvents() {{
                    try {{
                        const res = await fetch('/api/v1/events?limit=25', {{ headers: {{ 'Authorization': auth }} }});
                        const events = await res.json();
                        const eventsDiv = document.getElementById('events');
                        
                        const blockedCount = events.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH').length;
                        const totalRecent = events.length;
                        const blockRate = totalRecent ? Math.round((blockedCount / totalRecent) * 100) : 0;
                        document.getElementById('block-rate').innerText = blockRate + '%';

                        eventsDiv.innerHTML = events.map(e => {{
                            const entities = e.details.detected_entities ? 
                                `<div style="margin-top:10px; display: flex; flex-wrap: wrap; gap: 8px; border-top: 1px dashed #333; padding-top: 10px;">${{e.details.detected_entities.map(ent => 
                                    `<span class="badge" style="color: var(--accent-red); border-color: var(--accent-red); display: flex; align-items: center; gap: 5px;">
                                        <i data-lucide="${{getIcon(ent)}}" style="width: 12px; height: 12px;"></i>
                                        ${{ent}}
                                    </span>`).join('')}}</div>` : '';

                            // Redaction Preview - Cyberpunk Style
                            const redactionPreview = e.details.original_snippet ? `
                                <details style="margin-top: 15px; border: 1px solid var(--text-dim); padding: 5px;">
                                    <summary style="cursor: pointer; font-size: 0.75rem; color: var(--text-dim); list-style: none; display: flex; align-items: center; gap: 8px;">
                                        <i data-lucide="crosshair" style="width: 14px; height: 14px;"></i>
                                        [ VIEW AUDIT LOG ]
                                    </summary>
                                    <div class="snippet-diff" style="padding: 10px; background: #000;">
                                        <div class="snippet-box">
                                            <div style="font-size: 0.65rem; color: var(--accent-red); margin-bottom: 4px; text-transform: uppercase;">>> THREAT DETECTED</div>
                                            <div style="color: var(--accent-red); word-break: break-all;">${{e.details.original_snippet}}</div>
                                        </div>
                                        <div class="snippet-box" style="border-left: 2px solid var(--text-main);">
                                            <div style="font-size: 0.65rem; color: var(--text-main); margin-bottom: 4px; text-transform: uppercase;">>> NEUTRALIZED</div>
                                            <div style="color: var(--text-main); font-weight: 600;">[REDACTED]</div>
                                        </div>
                                    </div>
                                </details>
                            ` : '';
                            
                            // Component Timings
                            let timingsHtml = '';
                            if (e.details.component_timings) {{
                                const times = e.details.component_timings;
                                const total = Object.values(times).reduce((a, b) => a + b, 0);
                                if (total > 0) {{
                                    const colors = ['var(--text-main)', 'var(--accent-cyan)', 'var(--accent-yellow)', 'var(--accent-red)'];
                                    timingsHtml = `
                                        <div style="margin-top: 12px;">
                                            <div class="timings-bar">
                                                ${{Object.entries(times).map(([k, v], i) => 
                                                    `<div class="timing-seg" style="width: ${{v/total*100}}%; background: ${{colors[i % colors.length]}}" title="${{k}}: ${{v.toFixed(1)}}ms"></div>`
                                                ).join('')}}
                                            </div>
                                            <div class="timing-legend">
                                                ${{Object.entries(times).map(([k, v], i) => 
                                                    `<span><i class="timing-dot" style="background:${{colors[i % colors.length]}}"></i>${{k.replace('_ms','').replace('_',' ')}}: ${{v.toFixed(1)}}ms</span>`
                                                ).join('')}}
                                                <span style="margin-left:auto; color: #666;">TOT: ${{total.toFixed(1)}}ms</span>
                                            </div>
                                        </div>
                                    `;
                                }}
                            }}

                            const severityMap = {{
                                'CRITICAL': {{ color: 'var(--accent-red)', icon: 'shield-alert' }},
                                'HIGH': {{ color: 'var(--accent-red)', icon: 'alert-triangle' }},
                                'INFO': {{ color: 'var(--text-main)', icon: 'check-circle' }}, 
                                'LOW': {{ color: 'var(--text-main)', icon: 'check-circle' }},
                                'MEDIUM': {{ color: 'var(--accent-yellow)', icon: 'alert-circle' }}
                            }};
                            
                            const sev = severityMap[e.severity.toUpperCase()] || {{ color: '#666', icon: 'activity' }};
                            
                            let friendlyTitle = e.event_type.toUpperCase().replace('_', ' ');

                            return `
                                <div class="event-card ${{e.severity.toLowerCase()}}" style="border-left-color: ${{sev.color}}">
                                    <div class="header-flex" style="margin-bottom: 5px; border-bottom: none;">
                                        <div style="display: flex; align-items: center; gap: 8px;">
                                            <i data-lucide="${{sev.icon}}" style="width: 16px; height: 16px; color: ${{sev.color}}"></i>
                                            <span class="severity" style="color: ${{sev.color}}">${{e.severity}}</span>
                                        </div>
                                        <span class="timestamp" title="${{new Date(e.timestamp * 1000).toLocaleString()}}">${{timeAgo(e.timestamp)}}</span>
                                    </div>
                                    <div style="font-weight: 800; font-size: 1.1rem; color: #fff; display: flex; align-items: center; gap: 10px; margin-bottom: 5px; letter-spacing: 1px;">
                                        ${{friendlyTitle}}
                                    </div>
                                    <div class="details">
                                        <div style="margin-bottom: 5px; color: #666; font-size: 0.75rem;">
                                            PATH: <span style="color: #ccc;">${{e.details.path || 'unknown'}}</span>
                                        </div>
                                        ${{e.details.reason ? `<div style="color: var(--accent-red); margin-bottom: 5px;">REASON: ${{e.details.reason}}</div>` : ''}}
                                        ${{e.details.prompt_preview ? `<div style="color: #aaa;">PROMPT: "${{e.details.prompt_preview}}..."</div>` : ''}}
                                        ${{redactionPreview}}
                                        ${{entities}}
                                        ${{timingsHtml}}
                                    </div>
                                </div>
                            `;
                        }}).join('');
                        lucide.createIcons();
                    }} catch (e) {{ console.error("Events fetch failed", e); }}
                }}

                setInterval(() => {{
                    updateStats();
                    updateEvents();
                }}, 3000);
                
                updateStats();
                updateEvents();
            </script>
        </body>
    </html>
    """

@app.get("/api/v1/events")
async def get_events(limit: int = 50):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    
    return [
        {
            "id": r[0],
            "guardian_id": r[1],
            "event_type": r[2],
            "severity": r[3],
            "details": json.loads(r[4]),
            "timestamp": r[5]
        } for r in rows
    ]

@app.get("/api/v1/audit-log")
async def get_audit_log(limit: int = 50, username: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Check if table exists (it might not if init_db ran on old schema)
    try:
        cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        return []
    conn.close()
    
    return [
        {
            "id": r[0],
            "guardian_id": r[1],
            "action": r[2],
            "user": r[3],
            "details": r[4],
            "timestamp": r[5],
            "signature": r[6]
        } for r in rows
    ]

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Just keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
