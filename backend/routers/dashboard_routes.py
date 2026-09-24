from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasicCredentials
import json
import sqlite3
import asyncio
from backend.auth import _jwt_decode
from backend.main import (
    DB_PATH,
    JWT_SECRET,
    _decode_jwt,
    _enforce_rbac_and_user_rate_limit,
    _extract_basic_credentials_from_header,
    _get_user_role,
    _validate_basic,
    manager,
)

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
):
    username: str | None = None

    # Primary path: standard Basic/Bearer header auth.
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token:
            try:
                payload = _decode_jwt(token)
                username = str(payload.get("sub", "")).strip() or None
            except Exception:  # noqa: BLE001
                username = None
    else:
        creds = _extract_basic_credentials_from_header(request)
        if creds:
            try:
                username = _validate_basic(HTTPBasicCredentials(username=creds[0], password=creds[1]))
            except Exception:  # noqa: BLE001
                username = None

    # Cookie Auth
    if not username:
        cookie_token = request.cookies.get("guardian_token")
        if cookie_token:
            try:
                payload = _decode_jwt(cookie_token)
                username = str(payload.get("sub", "")).strip() or None
            except Exception:
                username = None

    if not username:
        # Return HTML Login Page instead of 401
        return HTMLResponse(content="""
        <!DOCTYPE html>
        <html>
        <head>
            <title>GuardianAI // ACCESS CONTROL</title>
            <style>
                body { background: #121317; color: #f8f9fc; font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .login-box { border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 40px; width: 320px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); background: #18191d; }
                h1 { margin: 0 0 20px; font-size: 1.25rem; text-transform: uppercase; letter-spacing: 1px; text-align: center; color: #fff; font-weight: 700; }
                input { width: 100%; box-sizing: border-box; background: #212226; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 6px; color: #fff; padding: 10px 14px; margin-bottom: 15px; font-family: inherit; }
                input:focus { border-color: #3279f9; outline: none; }
                button { width: 100%; background: #3279f9; color: #fff; border: none; border-radius: 6px; padding: 12px; font-weight: bold; cursor: pointer; text-transform: uppercase; transition: background 0.2s; }
                button:hover { background: #4b8afc; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h1>System Access</h1>
                <form action="/login" method="post">
                    <input type="text" name="username" placeholder="IDENTITY" required autofocus autocomplete="off">
                    <input type="password" name="password" placeholder="CREDENTIAL" required>
                    <button type="submit">Initialize Session</button>
                </form>
            </div>
        </body>
        </html>
        """)

    role = _get_user_role(username)
    _enforce_rbac_and_user_rate_limit(request, {"username": username, "role": role}, {"admin", "auditor", "user"})

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp FROM security_events ORDER BY timestamp DESC LIMIT 30")
    events = cur.fetchall()
    conn.close()
    
    # Try to read config for mode visibility
    try:
        import yaml
        with open("../guardian/config/config.yaml", 'r') as f:
            config = yaml.safe_load(f)
            sec_mode = config.get('security_policies', {}).get('security_mode', 'Balanced')
            prev_strat = config.get('security_policies', {}).get('leak_prevention_strategy', 'Redact')
    except Exception:
        sec_mode = "Balanced"
        prev_strat = "Redact"

    return f"""
    <html>
        <head>
            <title>GuardianAI // SOC TERMINAL</title>
            <script src="https://unpkg.com/lucide@latest"></script>
            <style>
                :root {{
                    --bg-color: #121317;
                    --card-bg: #18191d;
                    --text-main: #f8f9fc;
                    --text-dim: #b2bbc5;
                    --accent-red: #ea4335;
                    --accent-cyan: #3279f9;
                    --accent-yellow: #fbbc05;
                    --border-color: rgba(225, 230, 236, 0.08);
                }}
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
                    background-color: var(--bg-color); 
                    color: var(--text-main); 
                    margin: 0; 
                    padding: 20px; 
                }}
                h1 {{ 
                    color: #fff; 
                    margin: 0; 
                    font-size: 1.4rem; 
                    text-transform: uppercase; 
                    letter-spacing: 1px;
                    font-weight: 700;
                }}
                .container {{ max-width: 1200px; margin: auto; }}
                
                .scanline {{
                    display: none;
                }}
 
                .event-card {{ 
                    background: var(--card-bg); 
                    border: 1px solid var(--border-color); 
                    padding: 16px; 
                    margin-bottom: 15px; 
                    border-left: 4px solid var(--accent-red); 
                    border-radius: 8px;
                    position: relative; 
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                    transition: all 0.2s;
                }}
                .event-card:hover {{ 
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3); 
                    border-color: var(--accent-cyan);
                }}
                .event-card.low, .event-card.info {{ border-left-color: var(--text-dim); }} 
                .event-card.medium {{ border-left-color: var(--accent-yellow); }}
                .event-card.high {{ border-left-color: var(--accent-red); }}
                .event-card.critical {{ border-left-color: var(--accent-red); }}
                
                .header-flex {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; }}
                .severity {{ text-transform: uppercase; font-weight: 800; font-size: 0.75rem; letter-spacing: 0.1em; }}
                .timestamp {{ color: var(--text-dim); font-size: 0.85rem; }}
                .details {{ 
                    background: #212226; 
                    padding: 12px; 
                    border: 1px solid var(--border-color); 
                    border-radius: 6px;
                    font-family: 'Courier New', monospace; 
                    margin-top: 15px; 
                    color: #ddd; 
                    font-size: 0.85rem; 
                    line-height: 1.5; 
                    overflow-x: auto; 
                }}
                .badge {{ 
                    background: #212226; 
                    padding: 6px 12px; 
                    border: 1px solid var(--border-color); 
                    border-radius: 6px;
                    font-size: 0.7rem; 
                    font-weight: 600; 
                    text-transform: uppercase; 
                    color: var(--text-main);
                }}
                .stat-card {{ 
                    background: var(--card-bg); 
                    border: 1px solid var(--border-color); 
                    border-radius: 8px;
                    padding: 20px; 
                    text-align: center; 
                    position: relative;
                }}
                .footnote {{ font-size: 0.65rem; color: var(--text-dim); margin-top: 8px; text-transform: uppercase; }}
                
                .mode-banner {{ 
                    background: var(--card-bg); 
                    border: 1px solid var(--border-color); 
                    border-radius: 8px;
                    padding: 12px 20px; 
                    margin-bottom: 25px; 
                    display: flex; 
                    align-items: center; 
                    gap: 20px; 
                }}
                
                .toast {{ 
                    position: fixed; bottom: 20px; right: 20px; 
                    background: var(--card-bg); color: var(--text-main); border: 1px solid var(--accent-cyan);
                    padding: 12px 24px; font-weight: 600; display: none; 
                    border-radius: 6px;
                    box-shadow: 0 4px 15px rgba(50, 121, 249, 0.2);
                    z-index: 1000; 
                }}
 
                .snippet-diff {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; font-size: 0.8rem; }}
                .snippet-box {{ 
                    background: #212226; 
                    padding: 10px; 
                    border-radius: 6px;
                    border: 1px solid var(--border-color); 
                }}
                
                /* Timings */
                .timings-bar {{ display: flex; height: 6px; overflow: hidden; margin-top: 10px; background: #212226; border-radius: 3px; }}
                .timing-seg {{ height: 100%; }}
                .timing-legend {{ display: flex; gap: 10px; font-size: 0.7rem; color: var(--text-dim); margin-top: 4px; flex-wrap: wrap; }}
                .timing-dot {{ width: 6px; height: 6px; display: inline-block; margin-right: 4px; border-radius: 50%; }}
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
                        <a href="/logout" class="badge" style="text-decoration:none; cursor:pointer; color: var(--accent-red); border-color: var(--accent-red);">[ LOGOUT ]</a>
                        <span class="badge" style="color: var(--accent-yellow); border-color: var(--accent-yellow);">V2.0 SECURE</span>
                    </div>
                </div>

                <!-- Security Warning (Hidden for Demo) -->
                <div style="background: rgba(255, 0, 60, 0.1); border: 1px solid var(--accent-red); padding: 10px; margin-bottom: 20px; text-align: center; color: var(--accent-red); font-weight: bold; font-size: 0.8rem; display: none;">
                    âš ï¸ WARNING: You are using default credentials. Set GUARDIAN_ADMIN_PASS environment variable immediately.
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
                         <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase;">BLOCK RATE (GLOBAL):</span>
                         <span id="block-rate" class="badge" style="color: var(--accent-red); border-color: var(--accent-red);">0%</span>
                         <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase; margin-left: 10px;">RECENT(25):</span>
                         <span id="block-rate-recent" class="badge" style="color: var(--accent-yellow); border-color: var(--accent-yellow);">0%</span>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px;">
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Total Ingress</div>
                        <div id="stat-total" style="font-size: 2rem; font-weight: 800; color: var(--text-main); text-shadow: 0 0 5px var(--text-main);">0</div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Upstream Latency</div>
                        <div id="stat-latency" style="font-size: 2rem; font-weight: 800; color: var(--accent-cyan); text-shadow: 0 0 5px var(--accent-cyan);">0ms</div>
                        <div class="footnote">MODEL + NETWORK TIME<br>(EXCLUDES GUARDIAN CHECKS)</div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Guardian Overhead</div>
                        <div id="stat-fastpath" style="font-size: 2rem; font-weight: 800; color: var(--accent-yellow); text-shadow: 0 0 5px var(--accent-yellow);">0</div>
                        <div class="footnote">FAST-PATH HITS: <span id="stat-fastpath-hits">0</span></div>
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
                        const res = await fetch('/api/v1/analytics', {{ credentials: 'same-origin' }});
                        const data = await res.json();
                        document.getElementById('stat-total').innerText = data.total_requests;
                        document.getElementById('stat-blocked').innerText = data.total_blocked;
                        document.getElementById('stat-latency').innerText = data.avg_upstream_ms + 'ms';
                        document.getElementById('stat-fastpath').innerText = data.avg_guardian_overhead_ms + 'ms';
                        document.getElementById('block-rate').innerText = data.global_block_rate_pct + '%';
                        document.getElementById('block-rate-recent').innerText = data.recent_block_rate_pct + '%';
                        
                        const fastHits = (data.path_breakdown.fast_path_keyword || 0) + 
                                         (data.path_breakdown.fast_path_threat_feed || 0) + 
                                         (data.path_breakdown.fast_path_allowlist || 0) +
                                         (data.path_breakdown.base64_filter || 0);
                        document.getElementById('stat-fastpath-hits').innerText = fastHits;
                    }} catch (e) {{ console.error("Analytics fetch failed", e); }}
                                function esc(s) {{ if (!s) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }}

                async function updateEvents() {{
                    try {{
                        const res = await fetch('/api/v1/events?limit=25', {{ credentials: 'same-origin' }});
                        const events = await res.json();
                        const eventsDiv = document.getElementById('events');
                        
                        eventsDiv.innerHTML = events.map(e => {{
                            const entities = e.details.detected_entities ? 
                                `<div style="margin-top:10px; display: flex; flex-wrap: wrap; gap: 8px; border-top: 1px dashed #333; padding-top: 10px;">${{e.details.detected_entities.map(ent => 
                                    `<span class="badge" style="color: var(--accent-red); border-color: var(--accent-red); display: flex; align-items: center; gap: 5px;">
                                        <i data-lucide="${{getIcon(ent)}}" style="width: 12px; height: 12px;"></i>
                                        ${{esc(ent)}}
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
                                            <div style="color: var(--accent-red); word-break: break-all;">${{esc(e.details.original_snippet)}}</div>
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
                                                    `<div class="timing-seg" style="width: ${{v/total*100}}%; background: ${{colors[i % colors.length]}}" title="${{esc(k)}}: ${{v.toFixed(1)}}ms"></div>`
                                                ).join('')}}
                                            </div>
                                            <div class="timing-legend">
                                                ${{Object.entries(times).map(([k, v], i) => 
                                                    `<span><i class="timing-dot" style="background:${{colors[i % colors.length]}}"></i>${{esc(k.replace('_ms','').replace('_',' '))}}: ${{v.toFixed(1)}}ms</span>`
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
                                <div class="event-card ${{esc(e.severity.toLowerCase())}}" style="border-left-color: ${{sev.color}}">
                                    <div class="header-flex" style="margin-bottom: 5px; border-bottom: none;">
                                        <div style="display: flex; align-items: center; gap: 8px;">
                                            <i data-lucide="${{sev.icon}}" style="width: 16px; height: 16px; color: ${{sev.color}}"></i>
                                            <span class="severity" style="color: ${{sev.color}}">${{esc(e.severity)}}</span>
                                        </div>
                                        <span class="timestamp" title="${{new Date(e.timestamp * 1000).toLocaleString()}}">${{timeAgo(e.timestamp)}}</span>
                                    </div>
                                    <div style="font-weight: 800; font-size: 1.1rem; color: #fff; display: flex; align-items: center; gap: 10px; margin-bottom: 5px; letter-spacing: 1px;">
                                        ${{esc(friendlyTitle)}}
                                    </div>
                                    <div class="details">
                                        <div style="margin-bottom: 5px; color: #666; font-size: 0.75rem;">
                                            PATH: <span style="color: #ccc;">${{esc(e.details.path || 'unknown')}}</span>
                                        </div>
                                        ${{e.details.reason ? `<div style="color: var(--accent-red); margin-bottom: 5px;">REASON: ${{esc(e.details.reason)}}</div>` : ''}}
                                        ${{e.details.prompt_preview ? `<div style="color: #aaa;">PROMPT: "${{esc(e.details.prompt_preview)}}..."</div>` : ''}}
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


@router.get("/site")
async def public_site():
    return HTMLResponse(
        f"""
        <html>
          <head><title>GuardianAI</title></head>
          <body>
            <h1>GuardianAI</h1>
            <p>Production-grade AI security gateway.</p>
            <p>Plans: <a href="/api/v1/public/plans">catalog</a></p>
          </body>
        </html>
        """
    )


@router.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    authenticated = False

    # 1. Inspect session cookie
    cookie_token = websocket.cookies.get("guardian_session")
    if cookie_token:
        try:
            payload = _jwt_decode(cookie_token, JWT_SECRET)
            if payload.get("role") in {"admin", "auditor"}:
                authenticated = True
        except (ValueError, TypeError, KeyError):
            pass

    # 2. Inspect query parameter (?token=...)
    if not authenticated:
        query_token = websocket.query_params.get("token")
        if query_token:
            try:
                payload = _jwt_decode(query_token, JWT_SECRET)
                if payload.get("role") in {"admin", "auditor"}:
                    authenticated = True
            except (ValueError, TypeError, KeyError):
                pass

    # 3. Inspect first text message within 10 seconds if not yet authenticated
    if not authenticated:
        try:
            message_str = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
            data = json.loads(message_str)
            token = data.get("token")
            if not token:
                raise ValueError("Missing token")
            payload = _jwt_decode(token, JWT_SECRET)
            if payload.get("role") in {"admin", "auditor"}:
                authenticated = True
            else:
                await websocket.close(code=1008)
                return
        except Exception:
            try:
                await websocket.send_json({"error": "unauthorized"})
                await websocket.close(code=1008)
            except Exception:
                pass
            return

    await manager.connect(websocket)
    try:
        while True:
            # Just keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
