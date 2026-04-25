"""
Notification Service
====================
Handles sending notifications via multiple channels:
  - Email (simulated / SMTP)
  - Slack (simulated / webhook)
  - SMS / PagerDuty (simulated)
  - Webhook integrations

"""

import asyncio
import json
from datetime import datetime
try:
    from backend.models import SecurityAlert, EscalationDecision
except ImportError:
    from models import SecurityAlert, EscalationDecision
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

# Simulated contact registry
CONTACT_CHANNELS = {
    "SOC Analyst": {
        "email": "soc-analyst@company.com",
        "slack": "#soc-alerts",
        "pagerduty": True,
        "sms": "+40700000001"
    },
    "SOC Lead": {
        "email": "soc-lead@company.com",
        "slack": "#soc-escalation",
        "pagerduty": True,
        "sms": "+40700000002"
    },
    "Security Manager": {
        "email": "sec-manager@company.com",
        "slack": "#security-management",
        "pagerduty": False,
        "sms": "+40700000003"
    },
    "CISO": {
        "email": "ciso@company.com",
        "slack": "#executive-security",
        "pagerduty": True,
        "sms": "+40700000004"
    },
    "CTO": {
        "email": "cto@company.com",
        "slack": "#executive-security",
        "pagerduty": True,
        "sms": "+40700000005"
    },
    "Incident Commander": {
        "email": "incident-commander@company.com",
        "slack": "#incident-command",
        "pagerduty": True,
        "sms": "+40700000006"
    },
    "System Owner": {
        "email": "sysowner@company.com",
        "slack": "#system-owners",
        "pagerduty": False,
        "sms": "+40700000007"
    },
    "Legal & Compliance": {
        "email": "legal@company.com",
        "slack": "#legal",
        "pagerduty": False,
        "sms": "+40700000008"
    },
    "PR / Communications": {
        "email": "pr@company.com",
        "slack": "#communications",
        "pagerduty": False,
        "sms": "+40700000009"
    },
    "Forensics Team": {
        "email": "forensics@company.com",
        "slack": "#forensics",
        "pagerduty": True,
        "sms": "+40700000010"
    }
}

# P1/P2 use all channels; P3 uses email+slack; P4 uses slack only
SEVERITY_CHANNEL_POLICY = {
    "P1": ["pagerduty", "sms", "email", "slack"],
    "P2": ["pagerduty", "email", "slack"],
    "P3": ["email", "slack"],
    "P4": ["slack"]
}


class NotificationService:

    async def notify(
        self,
        alert: SecurityAlert,
        classification: Dict[str, Any],
        escalation: EscalationDecision,
        ticket: dict
    ) -> List[dict]:
        """
        Send notifications to all parties in the escalation list.
        Returns a log of all notifications sent.
        """
        severity_code = classification["severity"]
        channels = SEVERITY_CHANNEL_POLICY.get(severity_code, ["slack"])
        notifications_sent = []

        tasks = []
        for person in escalation.notify:
            contact = CONTACT_CHANNELS.get(person)
            if not contact:
                continue
            for channel in channels:
                if channel in contact and contact[channel]:
                    tasks.append(
                        self._send_notification(
                            person, channel, contact[channel],
                            alert, classification, ticket
                        )
                    )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                notifications_sent.append(r)

        return notifications_sent

    async def _send_notification(
        self,
        person: str,
        channel: str,
        address: str,
        alert: SecurityAlert,
        classification: Dict[str, Any],
        ticket: dict
    ) -> dict:
        """Simulates sending a single notification."""
        await asyncio.sleep(0.05)  # Simulate network latency

        message = self._build_message(channel, alert, classification, ticket)

        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "recipient": person,
            "channel": channel,
            "address": address,
            "message_preview": message[:120] + "..." if len(message) > 120 else message,
            "status": "SENT",
            "ticket_id": ticket["id"]
        }

        logger.info(f"[{channel.upper()}] → {person} ({address}): {message[:80]}")
        return log_entry

    def _build_message(
        self,
        channel: str,
        alert: SecurityAlert,
        classification: Dict[str, Any],
        ticket: dict
    ) -> str:
        severity = classification["severity"]
        label = classification["severity_label"]
        category = classification["category"]

        if channel == "pagerduty":
            return json.dumps({
                "routing_key": "SIMULATED_KEY",
                "event_action": "trigger",
                "payload": {
                    "summary": f"[{severity}/{label}] {category}: {alert.type} on {alert.target}",
                    "severity": label.lower(),
                    "source": alert.source_ip,
                    "custom_details": {
                        "ticket_id": ticket["id"],
                        "target": alert.target,
                        "sla": f"{classification['sla_minutes']} minutes"
                    }
                }
            })

        elif channel == "sms":
            return (
                f"🚨 SECURITY ALERT [{severity}] {category}\n"
                f"Ticket: {ticket['id']}\n"
                f"Type: {alert.type} | Target: {alert.target}\n"
                f"SLA: {classification['sla_minutes']} min\n"
                f"Action required immediately!"
            )

        elif channel == "email":
            return (
                f"Subject: [{severity}/{label}] Security Incident - {ticket['id']}\n\n"
                f"A {label} security incident has been detected and requires your attention.\n\n"
                f"Incident ID  : {ticket['id']}\n"
                f"Type         : {alert.type}\n"
                f"Category     : {category}\n"
                f"Severity     : {severity}/{label}\n"
                f"Source IP    : {alert.source_ip}\n"
                f"Target       : {alert.target}\n"
                f"Detected by  : {alert.source}\n"
                f"SLA          : {classification['sla_minutes']} minutes\n\n"
                f"Risk Score   : {classification['risk_score']}/100\n\n"
                f"Please log into the Incident Response portal to review and act."
            )

        elif channel == "slack":
            return (
                f":rotating_light: *[{severity}/{label}] {category} Detected*\n"
                f">*Ticket:* `{ticket['id']}`\n"
                f">*Type:* {alert.type}  |  *Target:* {alert.target}\n"
                f">*Source IP:* {alert.source_ip}  |  *Detected by:* {alert.source}\n"
                f">*SLA:* {classification['sla_minutes']} minutes\n"
                f">*Risk Score:* {classification['risk_score']}/100\n"
                f":point_right: <https://ir-portal/tickets/{ticket['id']}|View Incident>"
            )

        return f"Security alert: {alert.type} on {alert.target} [{severity}] Ticket: {ticket['id']}"
