"""
Incident Classifier
===================
Implements a decision tree for classifying security alerts.
Inspired by NIST SP 800-61r2 and SANS Incident Response Process.

Decision Tree Structure:
  ROOT
  ├── Is data potentially compromised?
  │   ├── YES → Data Breach category
  │   │         ├── >100k records → P1/CRITICAL
  │   │         └── <100k records → P2/HIGH
  │   └── NO  → Check attack type
  │             ├── Active malware/ransomware → P1/CRITICAL
  │             ├── Network intrusion (active) → P2/HIGH
  │             ├── DoS affecting production → P2/HIGH
  │             ├── Brute force (>100 attempts) → P3/MEDIUM
  │             ├── Phishing (>10 victims) → P3/MEDIUM
  │             └── Other / reconnaissance → P4/LOW
"""

try:
    from backend.models import SecurityAlert
except ImportError:
    from models import SecurityAlert
from typing import Dict, Any


# Severity priorities aligned with NIST
SEVERITY_LEVELS = {
    "P1": {"label": "CRITICAL", "color": "#FF0000", "sla_minutes": 15},
    "P2": {"label": "HIGH",     "color": "#FF6600", "sla_minutes": 60},
    "P3": {"label": "MEDIUM",   "color": "#FFCC00", "sla_minutes": 240},
    "P4": {"label": "LOW",      "color": "#00CC44", "sla_minutes": 1440},
}


class IncidentClassifier:

    def classify(self, alert: SecurityAlert) -> Dict[str, Any]:
        """
        Main classification entry point.
        Returns a dict with severity, category, score, and decision trace.
        """
        trace = []
        severity, category, score = self._decision_tree(alert, trace)

        return {
            "severity": severity,
            "severity_label": SEVERITY_LEVELS[severity]["label"],
            "severity_color": SEVERITY_LEVELS[severity]["color"],
            "category": category,
            "risk_score": score,
            "sla_minutes": SEVERITY_LEVELS[severity]["sla_minutes"],
            "decision_trace": trace
        }

    def _decision_tree(self, alert: SecurityAlert, trace: list):
        """
        NIST-inspired decision tree for severity classification.
        Returns: (severity_code, category, risk_score)
        """
        alert_type = alert.type.lower()
        details = alert.details

        # ── NODE 1: Is this a confirmed data exfiltration / breach? ──────────
        trace.append("NODE_1: Is this a data exfiltration or breach event?")
        if alert_type in ("data_exfiltration", "data_breach"):
            trace.append("  → YES: Data breach category triggered")
            bytes_transferred = details.get("bytes_transferred", 0)
            records = details.get("records_affected", 0)

            trace.append(f"NODE_2: Volume check — bytes={bytes_transferred}, records={records}")
            if bytes_transferred > 100_000_000 or records > 10_000:
                trace.append("  → Massive exfiltration: P1/CRITICAL")
                return "P1", "Data Breach", 95
            else:
                trace.append("  → Limited exfiltration: P2/HIGH")
                return "P2", "Data Breach", 75

        trace.append("  → NO: Continue to attack type classification")

        # ── NODE 2: Ransomware / destructive malware? ─────────────────────────
        trace.append("NODE_2: Is this ransomware or destructive malware?")
        if alert_type == "malware_detected":
            malware_family = str(details.get("malware_family", "")).lower()
            ransomware_families = ["ryuk", "lockbit", "revil", "darkside", "conti", "blackcat", "cl0p"]

            if any(r in malware_family for r in ransomware_families):
                trace.append(f"  → RANSOMWARE detected ({malware_family}): P1/CRITICAL")
                return "P1", "Ransomware", 99
            elif malware_family in ["emotet", "trickbot", "qakbot", "dridex"]:
                trace.append(f"  → Banking trojan / loader ({malware_family}): P2/HIGH")
                return "P2", "Malware", 80
            else:
                trace.append(f"  → Generic malware ({malware_family}): P3/MEDIUM")
                return "P3", "Malware", 55

        trace.append("  → NO: Continue")

        # ── NODE 3: Active network intrusion? ────────────────────────────────
        trace.append("NODE_3: Is this an active network intrusion?")
        if alert_type in ("unauthorized_access", "lateral_movement", "privilege_escalation"):
            target = str(alert.target).lower()
            critical_targets = ["database", "prod", "dc", "domain-controller", "backup", "financial"]

            if any(ct in target for ct in critical_targets):
                trace.append(f"  → Critical system targeted ({alert.target}): P1/CRITICAL")
                return "P1", "Intrusion", 90
            else:
                trace.append(f"  → Non-critical system targeted ({alert.target}): P2/HIGH")
                return "P2", "Intrusion", 70

        trace.append("  → NO: Continue")

        # ── NODE 4: Denial of Service? ────────────────────────────────────────
        trace.append("NODE_4: Is this a DoS/DDoS attack?")
        if alert_type == "ddos":
            rps = details.get("requests_per_second", 0)
            if rps > 10_000:
                trace.append(f"  → Large-scale DDoS ({rps} rps): P2/HIGH")
                return "P2", "DoS", 72
            else:
                trace.append(f"  → Moderate DoS ({rps} rps): P3/MEDIUM")
                return "P3", "DoS", 50

        trace.append("  → NO: Continue")

        # ── NODE 5: Brute force attacks ───────────────────────────────────────
        trace.append("NODE_5: Is this a brute force / credential stuffing attack?")
        if alert_type in ("brute_force", "credential_stuffing"):
            attempts = details.get("attempts", 0)
            duration = details.get("duration_minutes", 60)
            rate = attempts / max(duration, 1)

            if attempts > 1000 or rate > 100:
                trace.append(f"  → Aggressive brute force ({attempts} attempts, {rate:.0f}/min): P2/HIGH")
                return "P2", "Credential Attack", 65
            elif attempts > 100:
                trace.append(f"  → Moderate brute force ({attempts} attempts): P3/MEDIUM")
                return "P3", "Credential Attack", 45
            else:
                trace.append(f"  → Low-volume brute force ({attempts} attempts): P4/LOW")
                return "P4", "Credential Attack", 20

        trace.append("  → NO: Continue")

        # ── NODE 6: Phishing ──────────────────────────────────────────────────
        trace.append("NODE_6: Is this a phishing / social engineering event?")
        if alert_type in ("phishing_reported", "phishing", "spear_phishing"):
            victims = details.get("victims_clicked", 0)
            if victims > 20:
                trace.append(f"  → Mass phishing campaign ({victims} victims): P2/HIGH")
                return "P2", "Phishing", 68
            elif victims > 5:
                trace.append(f"  → Targeted phishing ({victims} victims): P3/MEDIUM")
                return "P3", "Phishing", 42
            else:
                trace.append(f"  → Isolated phishing ({victims} victim(s)): P4/LOW")
                return "P4", "Phishing", 18

        trace.append("  → NO: Continue")

        # ── NODE 7: Reconnaissance / scanning ────────────────────────────────
        trace.append("NODE_7: Is this a reconnaissance or scanning event?")
        if alert_type in ("port_scan", "vulnerability_scan", "reconnaissance"):
            trace.append("  → Reconnaissance activity: P4/LOW")
            return "P4", "Reconnaissance", 15

        # ── DEFAULT: Unknown / unclassified ──────────────────────────────────
        trace.append("NODE_DEFAULT: Unclassified alert type — defaulting to P3/MEDIUM pending review")
        return "P3", "Unknown", 35
