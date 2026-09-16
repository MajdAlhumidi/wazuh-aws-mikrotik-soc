import os
import json
from datetime import datetime
from typing import List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import chromadb

app = FastAPI(title="Cyber SOC Command Center")

CHROMA_DB_PATH = "/home/ubuntu/soc-ai-agent/incident_vector_db"

def get_real_incidents_from_chroma() -> List[Dict[str, Any]]:
    """قراءة جميع السجلات الحقيقية الدائمة من ChromaDB"""
    try:
        if not os.path.exists(CHROMA_DB_PATH):
            return []
        
        client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        collection = client.get_collection("security_incidents")
        data = collection.get()

        if not data or not data.get("ids"):
            return []

        real_incidents = []
        total = len(data["ids"])

        for i in reversed(range(total)):
            case_id = data["ids"][i]
            meta = data["metadatas"][i] if data.get("metadatas") else {}
            cls = meta.get("classification", "unknown").lower()
            is_tp = "true" in cls

            host = meta.get("destination_ip", "local-agent")
            src_ip = meta.get("source_ip", "N/A")
            user = meta.get("user_account", "N/A")
            rule = meta.get("rule_name", "Security Alert")
            notes = meta.get("analyst_notes", "No investigation notes recorded.")

            real_incidents.append({
                "case_id": case_id,
                "time": meta.get("timestamp", datetime.now().strftime("%H:%M:%S")),
                "host_agent": host if host != "N/A" else "local-agent",
                "level": 10 if is_tp else 7,
                "rule_name": rule,
                "verdict": "Critical TP" if is_tp else "Benign/FP",
                "containment": "Isolated" if is_tp else "Active",
                "details": notes,
                "source_ip": src_ip,
                "user": user
            })

        return real_incidents
    except Exception as e:
        print(f"[!] Error fetching from ChromaDB: {e}")
        return []

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

class ExternalAlertInput(BaseModel):
    case_id: str = ""
    rule_level: int = 7
    rule_desc: str = ""
    target_host: str = ""
    source_ip: str = ""
    payload: str = ""
    report_text: str = ""
    classification: str = ""

@app.post("/api/broadcast")
async def ingest_real_agent_alert(alert: ExternalAlertInput):
    """بث التقرير المحفوظ في ChromaDB إلى المتصفح لحظياً"""
    is_tp = "TRUE" in alert.classification.upper()
    now_time = datetime.now().strftime("%H:%M:%S")

    new_record = {
        "case_id": alert.case_id if alert.case_id else f"INC-{datetime.now().strftime('%Y%m%d')}-LIVE",
        "time": now_time,
        "host_agent": alert.target_host,
        "level": alert.rule_level,
        "rule_name": alert.rule_desc,
        "verdict": "Critical TP" if is_tp else "Benign/FP",
        "containment": "Isolated" if is_tp else "Active",
        "details": alert.report_text,
        "source_ip": alert.source_ip,
        "user": "N/A"
    }

    await manager.broadcast({"type": "NEW_ALERT", "incident": new_record})
    return {"status": "broadcasted", "case_id": new_record["case_id"]}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        initial_data = get_real_incidents_from_chroma()
        await websocket.send_json({"type": "INIT_DATA", "incidents": initial_data})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cyber SOC Command Center</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #0b0c10;
      color: #e2e8f0;
      font-family: 'Inter', sans-serif;
      padding: 30px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .container { max-width: 1100px; margin: 0 auto; width: 100%; }
    h1 { font-size: 24px; font-weight: 500; color: #ffffff; margin-bottom: 24px; }
    .soc-table { width: 100%; border-collapse: separate; border-spacing: 0 4px; margin-bottom: 24px; }
    .soc-table th { text-align: left; font-size: 11px; font-weight: 500; color: #94a3b8; padding: 10px 14px; border-bottom: 1px solid #1e222d; }
    .soc-table tbody tr { cursor: pointer; transition: background 0.15s ease; }
    .soc-table td { padding: 12px 14px; font-size: 11.5px; white-space: nowrap; }
    
    tr.row-critical { background-color: #211216; color: #fca5a5; }
    tr.row-critical td:first-child { border-top-left-radius: 4px; border-bottom-left-radius: 4px; }
    tr.row-critical td:last-child { border-top-right-radius: 4px; border-bottom-right-radius: 4px; }
    tr.row-critical:hover { background-color: #2e161c; }

    tr.row-benign { background-color: #121c2e; color: #7dd3fc; }
    tr.row-benign td:first-child { border-top-left-radius: 4px; border-bottom-left-radius: 4px; }
    tr.row-benign td:last-child { border-top-right-radius: 4px; border-bottom-right-radius: 4px; }
    tr.row-benign:hover { background-color: #182740; }

    tr.selected { outline: 1px solid rgba(255, 255, 255, 0.4); }

    .detail-card {
      margin-top: 15px;
      padding: 16px 20px;
      background: #11141c;
      border: 1px solid #1e222d;
      border-radius: 8px;
    }
    .detail-card .target-title { font-size: 12px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #ffffff; margin-bottom: 6px; }
    .detail-card .verdict-badge { font-size: 12px; font-weight: 700; margin-bottom: 12px; }
    .detail-card .details-desc {
      font-size: 11.5px;
      color: #cbd5e1;
      line-height: 1.6;
      white-space: pre-wrap;
      font-family: monospace;
      max-height: 250px;
      overflow-y: auto;
      background: #080a0f;
      padding: 12px;
      border-radius: 6px;
      border: 1px solid #1a1f2c;
    }

    .metrics-bar { display: flex; align-items: center; justify-content: center; gap: 50px; padding: 20px 0; }
    .metric-item { text-align: center; position: relative; }
    .metric-item:not(:last-child)::after { content: ""; position: absolute; right: -25px; top: 50%; transform: translateY(-50%); width: 1px; height: 24px; background: #334155; }
    .metric-label { font-size: 9px; letter-spacing: 0.05em; text-transform: uppercase; color: #94a3b8; margin-bottom: 4px; }
    .metric-value { font-size: 14px; font-weight: 700; color: #ffffff; }

    .controls-bar { background-color: #12141a; border: 1px solid #1e222d; border-radius: 8px; padding: 12px 18px; display: flex; align-items: center; justify-content: space-between; }
    .filter-group { display: flex; align-items: center; gap: 12px; font-size: 11px; color: #cbd5e1; }
    .filter-selector { display: flex; align-items: center; gap: 14px; cursor: pointer; user-select: none; }
    .filter-arrow { color: #64748b; font-size: 12px; }
    .filter-value { font-weight: 600; color: #ffffff; }

    .btn-refresh { background: #1e222d; border: 1px solid #2d3342; color: #ffffff; padding: 6px 14px; border-radius: 6px; font-size: 11px; font-weight: 500; cursor: pointer; }
    .btn-refresh:hover { background: #2a3040; }
  </style>
</head>
<body>

  <div class="container">
    <h1>Cyber SOC Command Center</h1>

    <table class="soc-table">
      <thead>
        <tr>
          <th>Case ID</th>
          <th>Time</th>
          <th>Host Agent</th>
          <th>Level</th>
          <th>Rule Name</th>
          <th>Verdict</th>
          <th>Containment</th>
        </tr>
      </thead>
      <tbody id="incidents-tbody"></tbody>
    </table>

    <div class="detail-card">
      <div id="target-title" class="target-title">SELECT AN INCIDENT</div>
      <div id="verdict-badge" class="verdict-badge">---</div>
      <div id="details-desc" class="details-desc">Select an incident from the table above to read the actual Gemini investigation report from ChromaDB.</div>
    </div>

    <div class="metrics-bar">
      <div class="metric-item">
        <div class="metric-label">REAL INCIDENTS IN DB</div>
        <div id="metric-total" class="metric-value">0</div>
      </div>
      <div class="metric-item">
        <div class="metric-label">CONFIRMED ATTACKS (TP)</div>
        <div id="metric-tp" class="metric-value">0</div>
      </div>
      <div class="metric-item">
        <div class="metric-label">BENIGN FILTERED (FP)</div>
        <div id="metric-fp" class="metric-value">0</div>
      </div>
    </div>

    <div class="controls-bar">
      <div class="filter-group">
        <span>Filter</span>
        <div class="filter-selector" onclick="cycleFilter()">
          <span class="filter-arrow">&lsaquo;</span>
          <span id="filter-text" class="filter-value">All</span>
          <span class="filter-arrow">&rsaquo;</span>
        </div>
      </div>
      <button class="btn-refresh" onclick="location.reload()">Reload DB Records</button>
    </div>
  </div>

  <script>
    let allIncidents = [];
    let selectedId = null;
    let currentFilter = "All";
    const filterOptions = ["All", "Critical TP", "Benign/FP"];

    const tbody = document.getElementById('incidents-tbody');
    const targetTitle = document.getElementById('target-title');
    const verdictBadge = document.getElementById('verdict-badge');
    const detailsDesc = document.getElementById('details-desc');
    const filterText = document.getElementById('filter-text');

    function connectWS() {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${window.location.host}/ws`);

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "INIT_DATA") {
          allIncidents = data.incidents;
          if (allIncidents.length > 0 && !selectedId) selectedId = allIncidents[0].case_id;
          render();
        } else if (data.type === "NEW_ALERT") {
          allIncidents.unshift(data.incident);
          selectedId = data.incident.case_id;
          render();
        }
      };

      ws.onclose = () => setTimeout(connectWS, 2000);
    }

    function render() {
      tbody.innerHTML = '';
      
      const filtered = allIncidents.filter(inc => {
        if (currentFilter === "All") return true;
        return inc.verdict === currentFilter;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#64748b;padding:20px;">No incidents found in ChromaDB</td></tr>';
      }

      filtered.forEach(inc => {
        const tr = document.createElement('tr');
        const isCritical = inc.verdict.includes("Critical") || inc.verdict.includes("TP");
        tr.className = isCritical ? 'row-critical' : 'row-benign';
        if (inc.case_id === selectedId) tr.classList.add('selected');

        tr.onclick = () => selectIncident(inc.case_id);

        tr.innerHTML = `
          <td>${inc.case_id}</td>
          <td>${inc.time}</td>
          <td>${inc.host_agent}</td>
          <td>${inc.level}</td>
          <td>${inc.rule_name}</td>
          <td>${inc.verdict}</td>
          <td>${inc.containment}</td>
        `;
        tbody.appendChild(tr);
      });

      updateMetrics();
      updateDetailCard();
    }

    function selectIncident(id) {
      selectedId = id;
      render();
    }

    function updateDetailCard() {
      const item = allIncidents.find(x => x.case_id === selectedId);
      if (!item) return;

      targetTitle.innerText = `${item.case_id} - HOST: ${item.host_agent.toUpperCase()}`;
      verdictBadge.innerText = `VERDICT: ${item.verdict.toUpperCase()}`;
      verdictBadge.style.color = item.verdict.includes("Critical") ? "#fca5a5" : "#7dd3fc";
      detailsDesc.innerText = item.details;
    }

    function updateMetrics() {
      document.getElementById('metric-total').innerText = allIncidents.length;
      const tp = allIncidents.filter(x => x.verdict.includes("Critical")).length;
      const fp = allIncidents.filter(x => x.verdict.includes("Benign")).length;
      document.getElementById('metric-tp').innerText = tp;
      document.getElementById('metric-fp').innerText = fp;
    }

    function cycleFilter() {
      let idx = filterOptions.indexOf(currentFilter);
      idx = (idx + 1) % filterOptions.length;
      currentFilter = filterOptions[idx];
      filterText.innerText = currentFilter;
      render();
    }

    connectWS();
  </script>
</body>
</html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
