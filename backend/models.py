from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid


class SecurityAlert(BaseModel):
    id: Optional[str] = None
    type: str  # brute_force, malware_detected, data_exfiltration, unauthorized_access, ddos, phishing_reported, etc.
    source_ip: str
    target: str
    details: Dict[str, Any] = {}
    source: str = "SIEM"  # SIEM, EDR, DLP, WAF, IDS, Manual
    received_at: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "type": "brute_force",
                "source_ip": "185.220.101.45",
                "target": "auth-service",
                "details": {"attempts": 250, "duration_minutes": 5},
                "source": "SIEM"
            }
        }


class EscalationDecision(BaseModel):
    severity: str  # P1/CRITICAL, P2/HIGH, P3/MEDIUM, P4/LOW
    category: str  # Intrusion, Malware, Data Breach, DoS, Phishing, Other
    notify: List[str]  # list of roles/people to notify
    path: List[str]  # escalation path steps
    sla_minutes: int  # response SLA
    containment_actions: List[str]
    decision_trace: List[str]  # how the decision tree was traversed

    def dict(self, **kwargs):
        return {
            "severity": self.severity,
            "category": self.category,
            "notify": self.notify,
            "path": self.path,
            "sla_minutes": self.sla_minutes,
            "containment_actions": self.containment_actions,
            "decision_trace": self.decision_trace
        }


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert: SecurityAlert
    classification: Dict[str, Any]
    escalation: EscalationDecision
    status: str = "OPEN"  # OPEN, IN_PROGRESS, CONTAINED, RESOLVED, CLOSED
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    assigned_to: Optional[str] = None
    notes: List[str] = []
