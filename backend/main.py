"""
Security Incident Notification & Escalation System
====================================================
Based on NIST SP 800-61r2 Incident Response Playbook
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path

from models import SecurityAlert, Incident, EscalationDecision
from classifier import IncidentClassifier
from escalation_engine import EscalationEngine
from ticket_manager import TicketManager
from notification_service import NotificationService

app = FastAPI(
    title="Security Incident Notification & Escalation System",
    description="Automated security incident workflow based on NIST SP 800-61r2",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
frontend_path = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

# Initialize components
classifier = IncidentClassifier()
escalation_engine = EscalationEngine()
ticket_manager = TicketManager()
notification_service = NotificationService()

# WebSocket connection manager for live dashboard
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()


@app.get("/")
async def serve_dashboard():
    return FileResponse(str(frontend_path / "index.html"))


@app.post("/api/alert", response_model=dict)
async def receive_alert(alert: SecurityAlert):
    """
    Main endpoint: receives a security alert and triggers the full workflow.
    Steps:
      1. Classify severity using the decision tree
      2. Create an incident ticket
      3. Determine escalation path
      4. Send notifications to appropriate personnel
    """
    alert.id = str(uuid.uuid4())
    alert.received_at = datetime.utcnow().isoformat()

    # Step 1: Classify the alert
    classification = classifier.classify(alert)
    
    # Step 2: Create incident ticket
    ticket = ticket_manager.create_ticket(alert, classification)
    
    # Step 3: Determine escalation path
    escalation = escalation_engine.determine_escalation(alert, classification)
    
    # Step 4: Send notifications
    notifications_sent = await notification_service.notify(
        alert, classification, escalation, ticket
    )
    
    # Update ticket with escalation info
    ticket_manager.update_ticket(ticket["id"], {
        "escalation_path": escalation.path,
        "notified_parties": escalation.notify,
        "notifications_sent": notifications_sent
    })

    incident = {
        "alert": alert.dict(),
        "classification": classification,
        "ticket": ticket,
        "escalation": escalation.dict(),
        "notifications_sent": notifications_sent,
        "workflow_completed_at": datetime.utcnow().isoformat()
    }

    # Broadcast to dashboard
    await manager.broadcast({
        "event": "new_incident",
        "data": incident
    })

    return incident


@app.get("/api/tickets")
async def get_tickets():
    return ticket_manager.get_all_tickets()


@app.get("/api/tickets/{ticket_id}")
async def get_ticket(ticket_id: str):
    ticket = ticket_manager.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@app.patch("/api/tickets/{ticket_id}")
async def update_ticket(ticket_id: str, updates: dict):
    ticket = ticket_manager.update_ticket(ticket_id, updates)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    await manager.broadcast({"event": "ticket_updated", "data": ticket})
    return ticket


@app.get("/api/playbook")
async def get_playbook():
    """Returns the escalation decision tree / playbook structure"""
    return escalation_engine.get_playbook()


@app.get("/api/stats")
async def get_stats():
    return ticket_manager.get_stats()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send current state on connect
        await websocket.send_json({
            "event": "init",
            "data": {
                "tickets": ticket_manager.get_all_tickets(),
                "stats": ticket_manager.get_stats()
            }
        })
        while True:
            await websocket.receive_text()  # Keep alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/api/simulate")
async def simulate_alert():
    """Generates a random realistic alert for demo purposes"""
    import random
    scenarios = [
        {
            "type": "brute_force",
            "source_ip": f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "target": "auth-service",
            "details": {"attempts": random.randint(50, 500), "duration_minutes": random.randint(1, 30)},
            "source": "SIEM"
        },
        {
            "type": "malware_detected",
            "source_ip": "10.0.0.45",
            "target": "workstation-HR-07",
            "details": {"malware_family": "Emotet", "file": "invoice.xlsm"},
            "source": "EDR"
        },
        {
            "type": "data_exfiltration",
            "source_ip": "10.0.1.12",
            "target": "fileserver-01",
            "details": {"bytes_transferred": random.randint(1000000, 500000000), "destination": "external"},
            "source": "DLP"
        },
        {
            "type": "unauthorized_access",
            "source_ip": "192.168.1.99",
            "target": "database-prod",
            "details": {"user": "svc_account", "action": "SELECT * FROM users"},
            "source": "SIEM"
        },
        {
            "type": "ddos",
            "source_ip": "multiple",
            "target": "web-gateway",
            "details": {"requests_per_second": random.randint(5000, 50000), "protocol": "HTTP"},
            "source": "WAF"
        },
        {
            "type": "phishing_reported",
            "source_ip": "smtp.external.com",
            "target": "mail-gateway",
            "details": {"victims_clicked": random.randint(1, 50), "domain": "micro5oft-login.com"},
            "source": "Email Security"
        },
    ]
    
    scenario = random.choice(scenarios)
    alert = SecurityAlert(**scenario)
    return await receive_alert(alert)
