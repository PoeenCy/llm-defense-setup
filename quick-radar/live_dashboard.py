#!/usr/bin/env python3
"""
live_defense_dashboard.py - BẢNG ĐIỀU KHIỂN GIÁM SÁT TÁC CHIẾN ATTACK-DEFENSE (THỜI GIAN THỰC)
- Tự động bắt stream Nginx access.log từ Vulnbox qua SSH.
- Tự động phân loại 20 đội đối thủ và nhận diện Checker Bot.
- Phát hiện đòn đánh, phân loại mức độ nguy hiểm, cảnh báo thời gian thực (Audio & Toast).
- Tích hợp AI / Local LLM (Ollama foundation-sec-8b-chat) giải mã payload dị và đề xuất vá tức thì.
- Giao diện Web trực quan tại http://localhost:8888.
"""

import os
import re
import sys
import json
import time
import asyncio
import urllib.request
import urllib.error
from datetime import datetime
from aiohttp import web

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# 1. ĐỌC CẤU HÌNH TỪ CONFIG.ENV
def load_config():
    cfg = {}
    for p in [os.path.join(ROOT_DIR, "config.env"), os.path.join(SCRIPT_DIR, "config.env")]:
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        cfg[k.strip()] = v.strip().strip('"').strip("'")
            break
    return cfg

CFG = load_config()
VULNBOX_IP = CFG.get("VULNBOX_IP", "10.13.2.10")
SSH_PORT = CFG.get("SSH_PORT", "2201")
SSH_USER = CFG.get("SSH_USER", "root")
SSH_KEY = os.path.expanduser(CFG.get("SSH_KEY", "~/.ssh/cyberknight_id"))
TOTAL_TEAMS = int(CFG.get("TOTAL_TEAMS", "20"))
MY_TEAM_ID = int(CFG.get("MY_TEAM_ID", "1"))
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "foundation-sec-8b-chat:latest"

# Bộ nhớ đệm dữ liệu
LOG_ENTRIES = []
MAX_ENTRIES = 500
TEAM_STATS = {}
SERVICE_STATS = {"uploadlog": 0, "chat": 0, "mathsays": 0, "other": 0}
CHECKER_STATS = {"total": 0, "ok": 0, "fail": 0, "last_seen": "Chưa có"}
CONNECTED_WEBSOCKETS = set()

# Regex phân tích log Nginx chuẩn
LOG_REGEX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+) "(.*?)" "(.*?)"')

def identify_team(ip):
    # Checker Bot
    if ip in ["10.13.1.10", "127.0.0.1"]:
        return {"id": 0, "name": "🤖 Checker Bot (BTC)", "type": "checker"}
    
    # Dải IP team thi đấu (vd 10.13.9.X hoặc 10.60.X.Y)
    m = re.search(r'\.([0-9]+)$', ip)
    if m:
        t_id = int(m.group(1))
        if t_id == MY_TEAM_ID:
            return {"id": t_id, "name": f"🚩 Đội Nhà (Team {t_id})", "type": "own"}
        if 1 <= t_id <= TOTAL_TEAMS or t_id > 0:
            return {"id": t_id, "name": f"⚔️ Team {t_id}", "type": "enemy"}
    return {"id": 999, "name": f"🌐 IP {ip}", "type": "enemy"}

def classify_threat(method, uri, status):
    uri_lower = uri.lower()
    
    # 1. Phát hiện Webshell & File Upload RCE
    if any(k in uri_lower for k in [".php", "cell.php", "shell.php", "s.php", "cmd=", "exec="]):
        if "logs/" in uri_lower or "upload" in uri_lower:
            return {"level": "CRITICAL", "label": "WEBSHELL RCE", "color": "#ff3860"}
        return {"level": "HIGH", "label": "PHP / SCRIPT CALL", "color": "#ff6b81"}
    
    # 2. Phát hiện Command Injection & Shell Metacharacters
    if any(k in uri_lower for k in ["/usr/share", "/flag", "flag-", "cat+", "cat%20", "nl%20", "f*"]):
        return {"level": "CRITICAL", "label": "COMMAND INJECTION", "color": "#ff3860"}
    
    # 3. Phát hiện Dump cờ PostgREST Chat
    if "api/messages" in uri_lower and method == "GET" and "id=eq." not in uri_lower:
        return {"level": "HIGH", "label": "FLAG DUMP (CHAT)", "color": "#ff9f43"}
    
    # 4. Trạng thái HTTP 403 (WAF đã chặn đứng)
    if status == "403":
        return {"level": "BLOCKED", "label": "WAF BLOCKED", "color": "#1dd1a1"}
    
    # 5. Checker Bot bình thường
    if status in ["200", "201"]:
        return {"level": "INFO", "label": "BENIGN / CHECKER", "color": "#54a0ff"}
        
    return {"level": "LOW", "label": "UNKNOWN", "color": "#8395a7"}

def parse_log_line(line):
    line = line.strip()
    match = LOG_REGEX.match(line)
    if not match:
        return None
    
    ip, dt_str, method, uri, status, bytes_sent, referer, ua = match.groups()
    team = identify_team(ip)
    threat = classify_threat(method, uri, status)
    
    # Xác định service
    svc = "other"
    if "log-api" in uri: svc = "uploadlog"
    elif "api/" in uri or "chat" in uri: svc = "chat"
    elif "mathsays" in uri: svc = "mathsays"
    
    entry = {
        "id": int(time.time() * 1000) % 1000000,
        "time": dt_str.split()[0] if dt_str else "",
        "ip": ip,
        "team": team,
        "method": method,
        "uri": uri,
        "status": status,
        "threat": threat,
        "service": svc,
        "ua": ua[:40] if ua else "-"
    }
    return entry

# WebSocket Handler
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CONNECTED_WEBSOCKETS.add(ws)
    
    # Gửi snapshot hiện tại khi vừa kết nối
    await ws.send_json({
        "type": "init",
        "entries": LOG_ENTRIES[-50:],
        "team_stats": TEAM_STATS,
        "service_stats": SERVICE_STATS,
        "checker_stats": CHECKER_STATS
    })
    
    try:
        async for msg in ws:
            pass
    finally:
        CONNECTED_WEBSOCKETS.discard(ws)
    return ws

async def broadcast(data):
    dead = set()
    for ws in CONNECTED_WEBSOCKETS:
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    for ws in dead:
        CONNECTED_WEBSOCKETS.discard(ws)

# API Phân tích AI bằng Ollama Local
async def ai_analyze_handler(request):
    data = await request.json()
    payload = data.get("payload", "")
    
    prompt = f"""You are a specialized CTF Attack-Defense cybersecurity analyst.
Analyze this captured HTTP request in 2 concise sentences:
1. Identify the attack technique or exploit (e.g. webshell execution, command injection, flag exfiltration, path traversal).
2. Recommend the fastest defensive action (e.g. Nginx regex block or code patch).

Captured HTTP Request:
{payload}

Analysis:"""

    req_body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "options": {"num_predict": 120, "temperature": 0.2},
        "stream": False
    }).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL, data=req_body, headers={"Content-Type": "application/json"})
    
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8")).get("response", "")
        analysis = await loop.run_in_executor(None, fetch)
        return web.json_response({"status": "ok", "analysis": analysis.strip()})
    except Exception as e:
        return web.json_response({"status": "error", "analysis": f"Không thể kết nối Ollama local: {e}"})

# Background Task đọc Log từ Vulnbox qua SSH Stream
async def stream_vulnbox_logs():
    ssh_key_opt = f"-i {SSH_KEY}" if os.path.isfile(SSH_KEY) else ""
    cmd = f'ssh -F /dev/null -p {SSH_PORT} -o StrictHostKeyChecking=no {ssh_key_opt} {SSH_USER}@{VULNBOX_IP} "tail -n 100 -F /var/log/nginx/access.log"'
    
    while True:
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="ignore")
                entry = parse_log_line(decoded)
                if not entry:
                    continue
                
                # Cập nhật thống kê
                LOG_ENTRIES.append(entry)
                if len(LOG_ENTRIES) > MAX_ENTRIES:
                    LOG_ENTRIES.pop(0)
                
                t_name = entry["team"]["name"]
                if entry["team"]["type"] == "enemy":
                    TEAM_STATS[t_name] = TEAM_STATS.get(t_name, 0) + 1
                
                SERVICE_STATS[entry["service"]] = SERVICE_STATS.get(entry["service"], 0) + 1
                
                if entry["team"]["type"] == "checker":
                    CHECKER_STATS["total"] += 1
                    if entry["status"] in ["200", "201"]:
                        CHECKER_STATS["ok"] += 1
                    else:
                        CHECKER_STATS["fail"] += 1
                    CHECKER_STATS["last_seen"] = datetime.now().strftime("%H:%M:%S")

                # Bắn cập nhật sang giao diện
                await broadcast({"type": "new_log", "entry": entry, "team_stats": TEAM_STATS, "service_stats": SERVICE_STATS, "checker_stats": CHECKER_STATS})
                
        except Exception as e:
            await asyncio.sleep(5)

# Giao diện HTML Dashboard
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>CTF Live Defense Dashboard & AI Radar</title>
    <style>
        :root {
            --bg: #0f111a;
            --card: #1a1d2e;
            --border: #2a2e45;
            --accent: #54a0ff;
            --danger: #ff3860;
            --success: #1dd1a1;
            --warning: #ff9f43;
            --text: #f1f2f6;
            --text-dim: #a4b0be;
        }
        body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); }
        header { background: var(--card); padding: 15px 25px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; font-size: 1.3rem; display: flex; align-items: center; gap: 10px; }
        .grid-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; padding: 20px; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 15px; }
        .card-title { font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 5px; }
        .card-value { font-size: 1.8rem; font-weight: bold; }
        .main-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; padding: 0 20px 20px; }
        .table-container { background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .table-header { padding: 12px 15px; border-bottom: 1px solid var(--border); font-weight: bold; display: flex; justify-content: space-between; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: rgba(0,0,0,0.2); color: var(--text-dim); }
        tr:hover { background: rgba(255,255,255,0.03); }
        .badge { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }
        .uri-code { font-family: monospace; word-break: break-all; color: #ced6e0; }
        .btn-ai { background: #5f27cd; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.75rem; }
        .btn-ai:hover { background: #341f97; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: var(--card); border: 1px solid var(--border); border-radius: 8px; width: 550px; padding: 20px; }
        .alert-banner { background: #ee5253; color: white; padding: 10px 20px; font-weight: bold; display: none; text-align: center; }
    </style>
</head>
<body>
    <div id="alertBanner" class="alert-banner">🚨 CẢNH BÁO TÁC CHIẾN: PHÁT HIỆN ĐÒN ĐÁNH NGUY HIỂM!</div>
    <header>
        <h1>🛡️ CTF DEFENSE RADAR & AI ASSISTANT</h1>
        <div id="statusDot" style="color: var(--success); font-size: 0.9rem;">● Trực Tiếp (SSH Connected)</div>
    </header>

    <div class="grid-stats">
        <div class="card">
            <div class="card-title">Tổng Request Giám Sát</div>
            <div class="card-value" id="reqCount">0</div>
        </div>
        <div class="card">
            <div class="card-title">Checker Bot SLA</div>
            <div class="card-value" id="slaHealth" style="color: var(--success);">100%</div>
            <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 4px;" id="checkerLast">Lần cuối: -</div>
        </div>
        <div class="card">
            <div class="card-title">Đòn Đánh Đã Chặn (403)</div>
            <div class="card-value" id="blockCount" style="color: var(--danger);">0</div>
        </div>
        <div class="card">
            <div class="card-title">Số Đội Tấn Công</div>
            <div class="card-value" id="enemyCount" style="color: var(--warning);">0</div>
        </div>
    </div>

    <div class="main-layout">
        <div class="table-container">
            <div class="table-header">
                <span>DÒNG SỰ KIỆN TÁC CHIẾN THỜI GIAN THỰC</span>
                <span style="font-size: 0.8rem; color: var(--text-dim);">Tự động cuộn theo log</span>
            </div>
            <div style="max-height: 600px; overflow-y: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Thời Gian</th>
                            <th>Nguồn</th>
                            <th>Service</th>
                            <th>URL & Payload</th>
                            <th>Status</th>
                            <th>Đánh Giá</th>
                            <th>AI</th>
                        </tr>
                    </thead>
                    <tbody id="logBody"></tbody>
                </table>
            </div>
        </div>

        <div>
            <div class="table-container" style="margin-bottom: 20px;">
                <div class="table-header">TOP ĐỘI ĐANG TẤN CÔNG (LEADERBOARD)</div>
                <div style="padding: 10px;">
                    <table style="width: 100%;">
                        <thead><tr><th>Đội</th><th>Số Lần Đánh</th></tr></thead>
                        <tbody id="enemyBody"></tbody>
                    </table>
                </div>
            </div>

            <div class="table-container">
                <div class="table-header">PHÂN BỐ TẤN CÔNG THEO DỊCH VỤ</div>
                <div style="padding: 15px;" id="serviceStatsDiv">
                    <div style="margin-bottom: 8px;">Uploadlog: <b id="svcUpload">0</b></div>
                    <div style="margin-bottom: 8px;">Chat API: <b id="svcChat">0</b></div>
                    <div>MathSays: <b id="svcMath">0</b></div>
                </div>
            </div>
        </div>
    </div>

    <div id="aiModal" class="modal">
        <div class="modal-content">
            <h3 style="margin-top:0;">🤖 AI TRỢ LÝ AN NINH (OLLAMA LOCAL)</h3>
            <p style="font-size: 0.85rem; color: var(--text-dim);" id="aiPayloadText"></p>
            <hr style="border: 0; border-top: 1px solid var(--border);">
            <div id="aiResult" style="padding: 10px 0; font-size: 0.95rem; line-height: 1.5;">Đang suy nghĩ và phân tích đòn đánh...</div>
            <div style="text-align: right; margin-top: 15px;">
                <button onclick="closeModal()" style="padding: 6px 15px; border: none; border-radius: 4px; background: var(--border); color: white; cursor: pointer;">Đóng</button>
            </div>
        </div>
    </div>

    <script>
        const ws = new WebSocket(`ws://${location.host}/ws`);
        const logBody = document.getElementById("logBody");
        const reqCount = document.getElementById("reqCount");
        const blockCount = document.getElementById("blockCount");
        const enemyCount = document.getElementById("enemyCount");
        const enemyBody = document.getElementById("enemyBody");
        const slaHealth = document.getElementById("slaHealth");
        const checkerLast = document.getElementById("checkerLast");
        const alertBanner = document.getElementById("alertBanner");
        let totalReq = 0, totalBlocked = 0;

        ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.type === "init") {
                data.entries.forEach(addLogRow);
                updateStats(data.team_stats, data.service_stats, data.checker_stats);
            } else if (data.type === "new_log") {
                addLogRow(data.entry);
                updateStats(data.team_stats, data.service_stats, data.checker_stats);
            }
        };

        function addLogRow(r) {
            totalReq++;
            if (r.status === "403") totalBlocked++;
            reqCount.innerText = totalReq;
            blockCount.innerText = totalBlocked;

            if (r.threat.level === "CRITICAL") {
                alertBanner.style.display = "block";
                alertBanner.innerText = `🚨 PHÁT HIỆN ĐÒN ĐÁNH TỪ ${r.team.name}: ${r.threat.label}`;
                setTimeout(() => { alertBanner.style.display = "none"; }, 5000);
            }

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="color: var(--text-dim); white-space:nowrap;">${r.time}</td>
                <td><b>${r.team.name}</b></td>
                <td><span class="badge" style="background:#2f3542;">${r.service}</span></td>
                <td class="uri-code">${r.method} ${r.uri}</td>
                <td><b style="color: ${r.status==='200'||r.status==='201'?'var(--success)':'var(--danger)'}">${r.status}</b></td>
                <td><span class="badge" style="background:${r.threat.color}; color:#fff;">${r.threat.label}</span></td>
                <td><button class="btn-ai" onclick='askAI(${JSON.stringify(r.method + " " + r.uri)})'>Phân Tích</button></td>
            `;
            logBody.insertBefore(tr, logBody.firstChild);
            if (logBody.children.length > 100) logBody.removeChild(logBody.lastChild);
        }

        function updateStats(teams, svcs, checker) {
            enemyCount.innerText = Object.keys(teams).length;
            enemyBody.innerHTML = Object.entries(teams)
                .sort((a,b) => b[1] - a[1])
                .map(([name, count]) => `<tr><td>${name}</td><td><b>${count}</b></td></tr>`)
                .join("");

            if (svcs) {
                document.getElementById("svcUpload").innerText = svcs.uploadlog || 0;
                document.getElementById("svcChat").innerText = svcs.chat || 0;
                document.getElementById("svcMath").innerText = svcs.mathsays || 0;
            }

            if (checker && checker.total > 0) {
                const percent = Math.round((checker.ok / checker.total) * 100);
                slaHealth.innerText = percent + "%";
                slaHealth.style.color = percent >= 95 ? "var(--success)" : "var(--danger)";
                checkerLast.innerText = "Lần cuối: " + checker.last_seen;
            }
        }

        function askAI(payload) {
            document.getElementById("aiModal").style.display = "flex";
            document.getElementById("aiPayloadText").innerText = payload;
            document.getElementById("aiResult").innerText = "Đang hỏi model an ninh mạng Foundation-Sec (Ollama)...";
            fetch("/api/analyze", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({payload})
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById("aiResult").innerText = data.analysis;
            })
            .catch(err => {
                document.getElementById("aiResult").innerText = "Lỗi: " + err;
            });
        }

        function closeModal() {
            document.getElementById("aiModal").style.display = "none";
        }
    </script>
</body>
</html>
"""

async def index_handler(request):
    return web.Response(text=DASHBOARD_HTML, content_type="text/html")

async def on_startup(app):
    app["log_task"] = asyncio.create_task(stream_vulnbox_logs())

async def on_cleanup(app):
    if "log_task" in app:
        app["log_task"].cancel()
        try:
            await app["log_task"]
        except asyncio.CancelledError:
            pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    app = web.Application()
    app.router.add_get("/", index_handler)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_post("/api/analyze", ai_analyze_handler)
    
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    
    print("=" * 70)
    print("    🛡️ CTF LIVE DEFENSE DASHBOARD & AI RADAR ĐÃ KHỞI ĐỘNG")
    print("=" * 70)
    print(f"[-] Mục tiêu Vulnbox     : {SSH_USER}@{VULNBOX_IP}:{SSH_PORT}")
    print(f"[-] AI Assistant Model  : {OLLAMA_MODEL} ({OLLAMA_URL})")
    print(f"[-] Truy cập Web UI tại : http://localhost:{port}")
    print("=" * 70)
    
    web.run_app(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    main()
