"""
Ticket Manager
==============
Creates, stores and manages incident tickets.
"""

import uuid
from datetime import datetime
from typing import Dict, Optional, List
try:
    from backend.models import SecurityAlert
except ImportError:
    from models import SecurityAlert

# In-memory ticket store (replace with DB in production)
_tickets: Dict[str, dict] = {}


class TicketManager:

    def create_ticket(self, alert: SecurityAlert, classification: dict) -> dict:
        ticket_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"

        ticket = {
            "id": ticket_id,
            "title": self._generate_title(alert, classification),
            "status": "OPEN",
            "severity": classification["severity"],
            "severity_label": classification["severity_label"],
            "severity_color": classification["severity_color"],
            "category": classification["category"],
            "risk_score": classification["risk_score"],
            "alert_type": alert.type,
            "source_ip": alert.source_ip,
            "target": alert.target,
            "source_system": alert.source,
            "details": alert.details,
            "sla_minutes": classification["sla_minutes"],
            "sla_deadline": self._compute_deadline(classification["sla_minutes"]),
            "escalation_path": [],
            "notified_parties": [],
            "notifications_sent": [],
            "decision_trace": classification["decision_trace"],
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "assigned_to": None,
            "timeline": [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "action": "Ticket created",
                    "actor": "Automated System",
                    "details": f"Alert received from {alert.source}. Classified as {classification['severity']}/{classification['severity_label']}."
                }
            ]
        }

        _tickets[ticket_id] = ticket
        return ticket

    def update_ticket(self, ticket_id: str, updates: dict) -> Optional[dict]:
        if ticket_id not in _tickets:
            return None

        ticket = _tickets[ticket_id]
        ticket.update(updates)
        ticket["updated_at"] = datetime.utcnow().isoformat()

        if "escalation_path" in updates:
            ticket["timeline"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "Escalation path set",
                "actor": "Automated System",
                "details": f"Escalation path determined. Notifying: {', '.join(updates.get('notified_parties', []))}"
            })

        _tickets[ticket_id] = ticket
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[dict]:
        return _tickets.get(ticket_id)

    def get_all_tickets(self) -> List[dict]:
        return sorted(_tickets.values(), key=lambda t: t["created_at"], reverse=True)

    def get_stats(self) -> dict:
        all_tickets = list(_tickets.values())
        by_severity = {}
        by_status = {}
        by_category = {}

        for t in all_tickets:
            s = t.get("severity_label", "UNKNOWN")
            by_severity[s] = by_severity.get(s, 0) + 1

            st = t.get("status", "UNKNOWN")
            by_status[st] = by_status.get(st, 0) + 1

            c = t.get("category", "UNKNOWN")
            by_category[c] = by_category.get(c, 0) + 1

        return {
            "total": len(all_tickets),
            "by_severity": by_severity,
            "by_status": by_status,
            "by_category": by_category
        }

    def _generate_title(self, alert: SecurityAlert, classification: dict) -> str:
        type_labels = {
            "brute_force": "Brute Force Attack",
            "malware_detected": "Malware Detection",
            "data_exfiltration": "Data Exfiltration Attempt",
            "unauthorized_access": "Unauthorized Access",
            "ddos": "DDoS Attack",
            "phishing_reported": "Phishing Campaign",
            "port_scan": "Port Scan / Reconnaissance",
            "credential_stuffing": "Credential Stuffing Attack",
            "ransomware": "Ransomware Detected",
            "lateral_movement": "Lateral Movement Detected",
        }
        label = type_labels.get(alert.type.lower(), alert.type.replace("_", " ").title())
        return f"[{classification['severity']}] {label} on {alert.target}"

    def _compute_deadline(self, sla_minutes: int) -> str:
        from datetime import timedelta
        deadline = datetime.utcnow() + timedelta(minutes=sla_minutes)
        return deadline.isoformat()
