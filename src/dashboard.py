from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
import json
import os

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Pull-state snapshot: last turn_update plus a capped event log.
# Written by /update (push from the orchestrator); read by /state (poll from Hermes/CLI).
_dashboard_latest: Dict[str, Any] = {}
_dashboard_log: List[Dict[str, Any]] = []
MAX_EVENT_LOG = 80


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
            try:
                await connection.send_text(message)
            except Exception:
                # Handle stale connections
                pass

manager = ConnectionManager()

class Update(BaseModel):
    event_type: str
    data: dict

@app.post("/update")
async def update_dashboard(update: Update):
    # Broadcast the update to all connected WS clients
    await manager.broadcast(json.dumps(update.dict()))

    # Keep a pollable snapshot + capped event log for CLI / Hermes / headless consumers
    global _dashboard_latest, _dashboard_log
    _dashboard_latest["event_type"] = update.event_type
    _dashboard_latest["data"] = update.data
    _dashboard_log.append(dict(_dashboard_latest))
    if len(_dashboard_log) > MAX_EVENT_LOG:
        _dashboard_log = _dashboard_log[-MAX_EVENT_LOG:]

    return {"status": "ok"}


@app.get("/state")
async def get_state() -> Dict[str, Any]:
    """
    Pollable snapshot of the last turn update plus the recent event log.
    For Hermes and headless consumers — no WebSocket required.
    """
    return {
        "latest": dict(_dashboard_latest),
        "event_log": list(_dashboard_log),
        "history_len": len(_dashboard_log),
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
async def get_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html", context={})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
