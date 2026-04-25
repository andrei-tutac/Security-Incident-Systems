"""
Tests for Security Incident Notification & Escalation System
=============================================================
Run with: pytest tests/
"""

import sys
sys.path.insert(0, '../backend')

import pytest
from unittest.mock import patch
from backend.models import SecurityAlert
from backend.classifier import IncidentClassifier
from backend.escalation_engine import EscalationEngine


@pytest.fixture
def classifier():
    return IncidentClassifier()

@pytest.fixture
def escalation_engine():
    return EscalationEngine()


# ── CLASSIFIER TESTS ──────────────────────────────────────────────────────────

class TestClassifier:

    def test_massive_data_exfiltration_is_p1(self, classifier):
        alert = SecurityAlert(
            type="data_exfiltration",
            source_ip="10.0.1.12",
            target="fileserver-01",
            details={"bytes_transferred": 500_000_000},
            source="DLP"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P1"
        assert result["category"] == "Data Breach"

    def test_small_exfiltration_is_p2(self, classifier):
        alert = SecurityAlert(
            type="data_exfiltration",
            source_ip="10.0.1.12",
            target="fileserver-01",
            details={"bytes_transferred": 1_000},
            source="DLP"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P2"

    def test_ransomware_is_p1(self, classifier):
        alert = SecurityAlert(
            type="malware_detected",
            source_ip="10.0.0.45",
            target="workstation-01",
            details={"malware_family": "LockBit"},
            source="EDR"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P1"
        assert result["category"] == "Ransomware"

    def test_banking_trojan_is_p2(self, classifier):
        alert = SecurityAlert(
            type="malware_detected",
            source_ip="10.0.0.45",
            target="workstation-01",
            details={"malware_family": "Emotet"},
            source="EDR"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P2"
        assert result["category"] == "Malware"

    def test_generic_malware_is_p3(self, classifier):
        alert = SecurityAlert(
            type="malware_detected",
            source_ip="10.0.0.45",
            target="workstation-01",
            details={"malware_family": "adware-generic"},
            source="EDR"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P3"

    def test_critical_system_intrusion_is_p1(self, classifier):
        alert = SecurityAlert(
            type="unauthorized_access",
            source_ip="192.168.1.99",
            target="database-prod",
            details={},
            source="SIEM"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P1"

    def test_noncritical_intrusion_is_p2(self, classifier):
        alert = SecurityAlert(
            type="unauthorized_access",
            source_ip="192.168.1.99",
            target="dev-server-01",
            details={},
            source="SIEM"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P2"

    def test_large_ddos_is_p2(self, classifier):
        alert = SecurityAlert(
            type="ddos",
            source_ip="multiple",
            target="web-gateway",
            details={"requests_per_second": 25000},
            source="WAF"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P2"

    def test_small_ddos_is_p3(self, classifier):
        alert = SecurityAlert(
            type="ddos",
            source_ip="multiple",
            target="web-gateway",
            details={"requests_per_second": 500},
            source="WAF"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P3"

    def test_aggressive_brute_force_is_p2(self, classifier):
        alert = SecurityAlert(
            type="brute_force",
            source_ip="185.220.101.45",
            target="auth-service",
            details={"attempts": 2000, "duration_minutes": 5},
            source="SIEM"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P2"

    def test_moderate_brute_force_is_p3(self, classifier):
        alert = SecurityAlert(
            type="brute_force",
            source_ip="185.220.101.45",
            target="auth-service",
            details={"attempts": 150, "duration_minutes": 30},
            source="SIEM"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P3"

    def test_low_brute_force_is_p4(self, classifier):
        alert = SecurityAlert(
            type="brute_force",
            source_ip="185.220.101.45",
            target="auth-service",
            details={"attempts": 20, "duration_minutes": 60},
            source="SIEM"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P4"

    def test_mass_phishing_is_p2(self, classifier):
        alert = SecurityAlert(
            type="phishing_reported",
            source_ip="smtp.external.com",
            target="mail-gateway",
            details={"victims_clicked": 50},
            source="Email Security"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P2"

    def test_targeted_phishing_is_p3(self, classifier):
        alert = SecurityAlert(
            type="phishing_reported",
            source_ip="smtp.external.com",
            target="mail-gateway",
            details={"victims_clicked": 8},
            source="Email Security"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P3"

    def test_port_scan_is_p4(self, classifier):
        alert = SecurityAlert(
            type="port_scan",
            source_ip="192.168.1.1",
            target="network",
            details={},
            source="IDS"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P4"

    def test_unknown_type_is_p3_default(self, classifier):
        alert = SecurityAlert(
            type="weird_unknown_type",
            source_ip="1.2.3.4",
            target="system",
            details={},
            source="SIEM"
        )
        result = classifier.classify(alert)
        assert result["severity"] == "P3"

    def test_decision_trace_is_populated(self, classifier):
        alert = SecurityAlert(
            type="brute_force",
            source_ip="1.2.3.4",
            target="auth",
            details={"attempts": 200, "duration_minutes": 10},
            source="SIEM"
        )
        result = classifier.classify(alert)
        assert len(result["decision_trace"]) > 0


# ── ESCALATION TESTS ──────────────────────────────────────────────────────────

class TestEscalationEngine:

    def _make_classification(self, severity, label, category, sla, score=50, trace=None):
        return {
            "severity": severity,
            "severity_label": label,
            "severity_color": "#ff0000",
            "category": category,
            "risk_score": score,
            "sla_minutes": sla,
            "decision_trace": trace or []
        }

    def test_p1_notifies_ciso_and_cto(self, escalation_engine):
        alert = SecurityAlert(type="ransomware", source_ip="10.0.0.1", target="srv", source="EDR")
        classification = self._make_classification("P1", "CRITICAL", "Ransomware", 15)
        result = escalation_engine.determine_escalation(alert, classification)
        assert "CISO" in result.notify
        assert "CTO" in result.notify
        assert "Incident Commander" in result.notify

    def test_p1_data_breach_includes_legal(self, escalation_engine):
        alert = SecurityAlert(type="data_exfiltration", source_ip="10.0.0.1", target="db", source="DLP")
        classification = self._make_classification("P1", "CRITICAL", "Data Breach", 15)
        result = escalation_engine.determine_escalation(alert, classification)
        assert "Legal & Compliance" in result.notify
        assert "PR / Communications" in result.notify

    def test_p2_notifies_soc_lead_and_manager(self, escalation_engine):
        alert = SecurityAlert(type="ddos", source_ip="multiple", target="web", source="WAF")
        classification = self._make_classification("P2", "HIGH", "DoS", 60)
        result = escalation_engine.determine_escalation(alert, classification)
        assert "SOC Lead" in result.notify
        assert "Security Manager" in result.notify
        assert "CISO" not in result.notify  # Not escalated to exec for P2

    def test_p3_notifies_only_soc_analyst(self, escalation_engine):
        alert = SecurityAlert(type="brute_force", source_ip="1.2.3.4", target="auth", source="SIEM")
        classification = self._make_classification("P3", "MEDIUM", "Credential Attack", 240)
        result = escalation_engine.determine_escalation(alert, classification)
        assert "SOC Analyst" in result.notify
        assert "CISO" not in result.notify
        assert "CTO" not in result.notify

    def test_p4_minimal_escalation(self, escalation_engine):
        alert = SecurityAlert(type="port_scan", source_ip="1.2.3.4", target="net", source="IDS")
        classification = self._make_classification("P4", "LOW", "Reconnaissance", 1440)
        result = escalation_engine.determine_escalation(alert, classification)
        assert "SOC Analyst" in result.notify
        assert len(result.notify) == 1

    def test_escalation_path_is_not_empty(self, escalation_engine):
        alert = SecurityAlert(type="brute_force", source_ip="1.2.3.4", target="auth", source="SIEM")
        classification = self._make_classification("P2", "HIGH", "Credential Attack", 60)
        result = escalation_engine.determine_escalation(alert, classification)
        assert len(result.path) > 0

    def test_containment_actions_returned(self, escalation_engine):
        alert = SecurityAlert(type="malware_detected", source_ip="10.0.0.1", target="ws", source="EDR")
        classification = self._make_classification("P1", "CRITICAL", "Ransomware", 15)
        result = escalation_engine.determine_escalation(alert, classification)
        assert len(result.containment_actions) > 0
        # Ransomware should mention isolation
        assert any("isolat" in a.lower() for a in result.containment_actions)

    def test_playbook_structure(self, escalation_engine):
        playbook = escalation_engine.get_playbook()
        assert "severity_matrix" in playbook
        assert "P1" in playbook["severity_matrix"]
        assert "decision_tree" in playbook
        assert "phases" in playbook


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
