"""
Escalation Engine
=================
Implements the escalation decision tree based on severity classification.
Follows NIST SP 800-61r2 and real-world incident response playbooks.

Escalation Matrix:
  P1/CRITICAL → CISO + SOC Lead + CTO + Incident Commander (15 min SLA)
  P2/HIGH     → SOC Lead + Security Manager + System Owner (1 hr SLA)
  P3/MEDIUM   → SOC Analyst + System Owner (4 hr SLA)
  P4/LOW      → SOC Analyst (24 hr SLA)
"""

try:
    from backend.models import SecurityAlert, EscalationDecision
except ImportError:
    from models import SecurityAlert, EscalationDecision
from typing import Dict, Any


# Organizational contacts (simulated)
CONTACTS = {
    "SOC Analyst": {
        "email": "soc-analyst@company.com",
        "phone": "+40-700-000-001",
        "slack": "#soc-alerts"
    },
    "SOC Lead": {
        "email": "soc-lead@company.com",
        "phone": "+40-700-000-002",
        "slack": "#soc-escalation"
    },
    "Security Manager": {
        "email": "sec-manager@company.com",
        "phone": "+40-700-000-003",
        "slack": "#security-management"
    },
    "CISO": {
        "email": "ciso@company.com",
        "phone": "+40-700-000-004",
        "slack": "#executive-security"
    },
    "CTO": {
        "email": "cto@company.com",
        "phone": "+40-700-000-005",
        "slack": "#executive-security"
    },
    "Incident Commander": {
        "email": "incident-commander@company.com",
        "phone": "+40-700-000-006",
        "slack": "#incident-command"
    },
    "System Owner": {
        "email": "sysowner@company.com",
        "phone": "+40-700-000-007",
        "slack": "#system-owners"
    },
    "Legal & Compliance": {
        "email": "legal@company.com",
        "phone": "+40-700-000-008",
        "slack": "#legal"
    },
    "PR / Communications": {
        "email": "pr@company.com",
        "phone": "+40-700-000-009",
        "slack": "#communications"
    },
    "Forensics Team": {
        "email": "forensics@company.com",
        "phone": "+40-700-000-010",
        "slack": "#forensics"
    }
}


class EscalationEngine:

    def determine_escalation(
        self,
        alert: SecurityAlert,
        classification: Dict[str, Any]
    ) -> EscalationDecision:
        """
        Determine who to notify and what actions to take based on classification.
        """
        severity = classification["severity"]
        category = classification["category"]
        trace = []

        notify, path, containment = self._escalation_tree(severity, category, alert, trace)

        return EscalationDecision(
            severity=f"{severity}/{classification['severity_label']}",
            category=category,
            notify=notify,
            path=path,
            sla_minutes=classification["sla_minutes"],
            containment_actions=containment,
            decision_trace=trace
        )

    def _escalation_tree(self, severity: str, category: str, alert: SecurityAlert, trace: list):
        """
        Maps severity + category to notification lists, escalation paths, and containment actions.
        """

        # ── P1: CRITICAL ─────────────────────────────────────────────────────
        if severity == "P1":
            trace.append("ESCALATION: P1/CRITICAL — Full executive escalation")
            trace.append("  → Immediate notification: CISO, CTO, Incident Commander")
            trace.append("  → SLA: 15 minutes to initial response")

            notify = ["SOC Lead", "SOC Analyst", "CISO", "CTO", "Incident Commander", "Forensics Team"]
            path = [
                "T+0min  : Alert auto-classified as P1/CRITICAL",
                "T+5min  : SOC Analyst acknowledges and begins triage",
                "T+10min : SOC Lead validates and escalates to CISO",
                "T+15min : Incident Commander activated, War Room opened",
                "T+30min : Containment actions executed",
                "T+60min : Status update to executive team",
                "T+4hr   : Forensic investigation initiated",
                "T+24hr  : Executive report and regulatory notification (if required)"
            ]

            if category in ("Data Breach", "Ransomware"):
                notify.append("Legal & Compliance")
                notify.append("PR / Communications")
                trace.append("  → Data breach/ransomware: Legal & PR added to notification list")
                path.append("T+2hr   : Legal team notified — GDPR/breach notification assessment")
                path.append("T+4hr   : PR team briefed for potential public disclosure")

            containment = self._containment_actions(category, "P1")

        # ── P2: HIGH ─────────────────────────────────────────────────────────
        elif severity == "P2":
            trace.append("ESCALATION: P2/HIGH — SOC + Security Management escalation")
            trace.append("  → Notification: SOC Lead, Security Manager, System Owner")
            trace.append("  → SLA: 60 minutes to initial response")

            notify = ["SOC Analyst", "SOC Lead", "Security Manager", "System Owner"]
            path = [
                "T+0min  : Alert auto-classified as P2/HIGH",
                "T+15min : SOC Analyst acknowledges and begins investigation",
                "T+30min : SOC Lead notified and reviews",
                "T+60min : Security Manager briefed",
                "T+2hr   : Containment strategy finalized",
                "T+4hr   : System Owner engaged for remediation",
                "T+8hr   : Status update to Security Manager",
                "T+24hr  : Incident report completed"
            ]
            containment = self._containment_actions(category, "P2")

        # ── P3: MEDIUM ────────────────────────────────────────────────────────
        elif severity == "P3":
            trace.append("ESCALATION: P3/MEDIUM — SOC Analyst handles, System Owner informed")
            trace.append("  → SLA: 4 hours to initial response")

            notify = ["SOC Analyst", "System Owner"]
            path = [
                "T+0min  : Alert auto-classified as P3/MEDIUM",
                "T+60min : SOC Analyst acknowledges",
                "T+4hr   : Investigation completed",
                "T+8hr   : System Owner notified with findings",
                "T+24hr  : Remediation actions applied",
                "T+48hr  : Incident closed or escalated"
            ]
            containment = self._containment_actions(category, "P3")

        # ── P4: LOW ───────────────────────────────────────────────────────────
        else:
            trace.append("ESCALATION: P4/LOW — Routine SOC investigation")
            trace.append("  → SLA: 24 hours to initial response")

            notify = ["SOC Analyst"]
            path = [
                "T+0min  : Alert logged as P4/LOW",
                "T+4hr   : SOC Analyst reviews during next shift",
                "T+24hr  : Investigation completed",
                "T+48hr  : Ticket closed or escalated if new evidence found"
            ]
            containment = self._containment_actions(category, "P4")

        return notify, path, containment

    def _containment_actions(self, category: str, severity: str) -> list:
        """Returns category-specific containment actions."""
        actions = {
            "Ransomware": [
                "IMMEDIATELY isolate affected systems from network",
                "Disconnect from domain — do NOT shut down (preserve memory forensics)",
                "Identify patient zero and scope of encryption",
                "Activate offline backup recovery plan",
                "Block C2 IPs/domains at firewall",
                "Engage ransomware negotiation firm if data is critical",
                "Notify FBI / law enforcement",
            ],
            "Data Breach": [
                "Identify and close the exfiltration vector",
                "Revoke compromised credentials immediately",
                "Enable enhanced logging on affected systems",
                "Block destination IPs/domains at firewall",
                "Assess GDPR/regulatory notification requirements (72hr clock)",
                "Preserve evidence chain-of-custody",
            ],
            "Intrusion": [
                "Block attacker IP at perimeter firewall",
                "Isolate compromised host(s) to quarantine VLAN",
                "Reset credentials for affected accounts",
                "Review and revert unauthorized changes",
                "Enable enhanced monitoring on adjacent systems",
            ],
            "Malware": [
                "Quarantine infected endpoint via EDR",
                "Block malware hashes at AV/EDR",
                "Block C2 domains/IPs at DNS and firewall",
                "Scan adjacent systems for lateral spread",
                "Identify initial infection vector",
            ],
            "DoS": [
                "Activate upstream DDoS scrubbing / CDN protection",
                "Enable rate limiting at WAF/load balancer",
                "Block attack source IPs at border firewall",
                "Scale infrastructure if capacity-based attack",
                "Notify ISP for upstream null-routing if needed",
            ],
            "Credential Attack": [
                "Temporarily lock targeted accounts after threshold",
                "Enable CAPTCHA / MFA enforcement",
                "Block attacking IP range at firewall",
                "Alert affected users to change passwords",
                "Review for successful unauthorized logins",
            ],
            "Phishing": [
                "Pull malicious emails from all mailboxes",
                "Block sender domain and URLs in email gateway",
                "Identify and isolate users who clicked",
                "Reset credentials of compromised users",
                "Conduct awareness notification to all staff",
            ],
            "Reconnaissance": [
                "Block scanning IP at firewall",
                "Log and monitor for follow-up attack activity",
                "Review exposed services on scanned ports",
            ],
        }

        default_actions = [
            "Document all findings in the incident ticket",
            "Monitor for escalation indicators",
            "Apply principle of least privilege review",
        ]

        return actions.get(category, default_actions)

    def get_playbook(self) -> dict:
        """Returns the full playbook / decision tree as structured data for the dashboard."""
        return {
            "name": "NIST SP 800-61r2 Incident Response Playbook",
            "version": "1.0",
            "phases": [
                {
                    "phase": 1,
                    "name": "Preparation",
                    "description": "Establish IR capability, tools, and contacts before incidents occur."
                },
                {
                    "phase": 2,
                    "name": "Detection & Analysis",
                    "description": "Alert ingestion, classification, and severity determination."
                },
                {
                    "phase": 3,
                    "name": "Containment, Eradication & Recovery",
                    "description": "Stop the bleeding, remove threat, restore operations."
                },
                {
                    "phase": 4,
                    "name": "Post-Incident Activity",
                    "description": "Lessons learned, report writing, process improvement."
                }
            ],
            "severity_matrix": {
                "P1": {
                    "label": "CRITICAL",
                    "sla": "15 min",
                    "notify": ["CISO", "CTO", "Incident Commander", "SOC Lead"],
                    "examples": ["Ransomware", "Active data exfiltration >100MB", "Unauthorized access to production DB"]
                },
                "P2": {
                    "label": "HIGH",
                    "sla": "1 hour",
                    "notify": ["SOC Lead", "Security Manager", "System Owner"],
                    "examples": ["Aggressive brute force", "Malware (banking trojan)", "Large DDoS"]
                },
                "P3": {
                    "label": "MEDIUM",
                    "sla": "4 hours",
                    "notify": ["SOC Analyst", "System Owner"],
                    "examples": ["Moderate brute force", "Generic malware", "Targeted phishing"]
                },
                "P4": {
                    "label": "LOW",
                    "sla": "24 hours",
                    "notify": ["SOC Analyst"],
                    "examples": ["Port scanning", "Isolated phishing", "Low-volume brute force"]
                }
            },
            "decision_tree": {
                "root": "Is data potentially exfiltrated?",
                "nodes": [
                    {
                        "id": "n1",
                        "question": "Is data exfiltrated?",
                        "yes": {"result": "Data Breach → n2"},
                        "no": {"next": "n3"}
                    },
                    {
                        "id": "n2",
                        "question": "Volume > 100MB or records > 10k?",
                        "yes": {"result": "P1/CRITICAL"},
                        "no": {"result": "P2/HIGH"}
                    },
                    {
                        "id": "n3",
                        "question": "Is it ransomware?",
                        "yes": {"result": "P1/CRITICAL"},
                        "no": {"next": "n4"}
                    },
                    {
                        "id": "n4",
                        "question": "Active network intrusion on critical system?",
                        "yes": {"result": "P1/CRITICAL"},
                        "no": {"next": "n5"}
                    },
                    {
                        "id": "n5",
                        "question": "DDoS > 10k rps?",
                        "yes": {"result": "P2/HIGH"},
                        "no": {"next": "n6"}
                    },
                    {
                        "id": "n6",
                        "question": "Brute force > 1000 attempts?",
                        "yes": {"result": "P2/HIGH"},
                        "no": {"next": "n7"}
                    },
                    {
                        "id": "n7",
                        "question": "Phishing > 20 victims?",
                        "yes": {"result": "P2/HIGH"},
                        "no": {"next": "n8"}
                    },
                    {
                        "id": "n8",
                        "question": "Reconnaissance / scanning?",
                        "yes": {"result": "P4/LOW"},
                        "no": {"result": "P3/MEDIUM (default)"}
                    }
                ]
            }
        }
