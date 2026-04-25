# 🛡 Security Incident Notification & Escalation System

> **Universitatea Politehnica Timisoara — Master Anul I SISC — SAC — Tutac Andrei Emanuel**  
> Sistem automat de clasificare, notificare și escaladare a incidentelor de securitate.  
> Inspirat din **NIST SP 800-61r2** (Computer Security Incident Handling Guide).

---

## Arhitectură

```
┌─────────────────────────────────────────────────────────────────┐
│                     WORKFLOW AUTOMAT                            │
│                                                                 │
│   SIEM / EDR / DLP / WAF                                        │
│         │                                                       │
│         ▼                                                       │
│   [1] POST /api/alert   ──►  Classifier (Arbore de decizie)     │
│                                     │                           │
│                                     ▼                           │
│                              Severitate (P1-P4)                 │
│                                     │                           │
│                                     ▼                           │
│                         [2] Ticket Manager  ──► INC-YYYYMMDD-   │
│                                     │                           │
│                                     ▼                           │
│                         [3] Escalation Engine                   │
│                              (Playbook NIST)                    │
│                                     │                           │
│                                     ▼                           │
│                         [4] Notification Service                │
│                          Email │ Slack │ SMS │ PagerDuty        │
│                                     │                           │
│                                     ▼                           │
│                         [5] WebSocket → Dashboard Live          │
└─────────────────────────────────────────────────────────────────┘
```

## Arbore de Decizie (Severitate)

```
                    ┌─────────────────────┐
                    │   Alerta Primita    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌────────────────────┐
                    │  Date exfiltrate?  │
                    └────────────────────┘
                     YES              NO
           ┌──────────┘                └──────────┐
           ▼                                      ▼
    ┌──────────────┐                    ┌────────────────────┐
    │ >100MB sau   │                    │ Ransomware?        │
    │ >10k records?│                    └────────────────────┘
    └──────────────┘                     YES               NO
     YES         NO                       │                 │
      │           │                    P1/CRIT              ▼
   P1/CRIT     P2/HIGH                            ┌────────────────────┐ 
                                                  |   Intruziune pe    | 
                                                  |   sistem critic?   | 
                                                  └────────────────────┘ 
                                                   YES               NO 
                                                    │                 │ 
                                                 P1/CRIT              ▼
                                                           ┌────────────────────┐
                                                           |   DDoS >10k rps?   |
                                                           └────────────────────┘
                                                            YES              NO
                                                             │                │
                                                          P2/HIGH             ▼   
                                                                      ┌───────────────┐
                                                                      |  BruteForce   |
                                                                      |  >1000 att?   |
                                                                      └───────────────┘
                                                                       YES          NO
                                                                        │            │
                                                                     P2/HIGH         ▼
                                                                             ┌──────────────┐
                                                                             |   Phishing   |
                                                                             | >20 victime? |
                                                                             └──────────────┘
                                                                              YES         NO
                                                                               │           │
                                                                            P2/HIGH     P3/MEDIUM
                                                                                        (default)
```

## Matricea de Escaladare (Playbook)

| Severitate | SLA Response | Notificați |
|------------|-------------|------------|
| **P1/CRITICAL** | ⏱ 15 minute | CISO, CTO, Incident Commander, SOC Lead, Forensics |
| **P2/HIGH** | ⏱ 60 minute | SOC Lead, Security Manager, System Owner |
| **P3/MEDIUM** | ⏱ 4 ore | SOC Analyst, System Owner |
| **P4/LOW** | ⏱ 24 ore | SOC Analyst |

> Data Breach + P1: se adaugă Legal & Compliance + PR/Communications (GDPR 72h clock!)

## Canale de Notificare per Severitate

| Severitate | PagerDuty | SMS | Email | Slack |
|------------|-----------|-----|-------|-------|
| P1/CRITICAL |   ✅ | ✅ | ✅ | ✅ |
| P2/HIGH |   ✅ | ❌ | ✅ | ✅ |
| P3/MEDIUM |   ❌ | ❌ | ✅ | ✅ |
| P4/LOW |   ❌ | ❌ | ❌ | ✅ |

---

## Setup & Rulare

### Cerințe
- Python 3.10+
- pip

### Instalare

```bash
cd backend
pip install -r requirements.txt
```

### Pornire server

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Accesare dashboard

```
http://localhost:8000
```

### Rulare teste

```bash
pip install pytest
pytest tests/ -v
```

---

## API Endpoints

| Method | Endpoint | Descriere |
|--------|----------|-----------|
| `POST` | `/api/alert` | Primește o alertă de securitate și rulează workflow-ul complet |
| `POST` | `/api/simulate` | Generează o alertă random pentru demo |
| `GET`  | `/api/tickets` | Listează toate ticketele de incident |
| `GET`  | `/api/tickets/{id}` | Detalii ticket |
| `PATCH`| `/api/tickets/{id}` | Actualizează un ticket |
| `GET`  | `/api/playbook` | Returnează arborele de decizie și playbook-ul |
| `GET`  | `/api/stats` | Statistici agregate |
| `WS`   | `/ws` | WebSocket pentru dashboard live |

### Exemplu Request

```bash
curl -X POST http://localhost:8000/api/alert \
  -H "Content-Type: application/json" \
  -d '{
    "type": "malware_detected",
    "source_ip": "10.0.0.45",
    "target": "workstation-HR-07",
    "details": {
      "malware_family": "LockBit",
      "file": "invoice.xlsm"
    },
    "source": "EDR"
  }'
```

### Exemplu Response

```json
{
  "alert": { "type": "malware_detected", ... },
  "classification": {
    "severity": "P1",
    "severity_label": "CRITICAL",
    "category": "Ransomware",
    "risk_score": 99,
    "sla_minutes": 15,
    "decision_trace": [
      "NODE_1: Is this a data exfiltration or breach event?",
      "  → NO: Continue to attack type classification",
      "NODE_2: Is this ransomware or destructive malware?",
      "  → RANSOMWARE detected (lockbit): P1/CRITICAL"
    ]
  },
  "ticket": {
    "id": "INC-20250101-ABC123",
    "title": "[P1] Malware Detection on workstation-HR-07",
    "status": "OPEN",
    ...
  },
  "escalation": {
    "severity": "P1/CRITICAL",
    "notify": ["SOC Lead", "CISO", "CTO", "Incident Commander", "Forensics Team"],
    "containment_actions": [
      "IMMEDIATELY isolate affected systems from network",
      ...
    ]
  },
  "notifications_sent": [
    { "recipient": "CISO", "channel": "pagerduty", "status": "SENT" },
    { "recipient": "CISO", "channel": "sms", "status": "SENT" },
    ...
  ]
}
```

---

## Structura Proiectului

```
security-incident-system/
├── __init__.py
├── conftest.py
├── backend/
|   ├── __init__.py
│   ├── main.py                 # FastAPI app + endpoints + WebSocket
│   ├── models.py               # Pydantic models (SecurityAlert, Incident, etc.)
│   ├── classifier.py           # Arbore de decizie pentru clasificarea severității
│   ├── escalation_engine.py    # Playbook NIST: escaladare + acțiuni de containment
│   ├── ticket_manager.py       # Gestionare tickete de incident
│   ├── notification_service.py # Email / Slack / SMS / PagerDuty (simulate)
│   └── requirements.txt
├── frontend/
│   └── index.html              # Dashboard live (WebSocket + dark UI)
├── tests/
|   ├── __init__.py
│   └── test_system.py          # Pytest: 18 teste pentru classifier + escalation
└── README.md
```

---

## Tipuri de Alerte Suportate

| Alert Type | Categorie | Severitate Tipică |
|------------|-----------|-------------------|
| `data_exfiltration` | Data Breach | P1/P2 |
| `malware_detected` | Ransomware/Malware | P1/P2/P3 |
| `unauthorized_access` | Intrusion | P1/P2 |
| `lateral_movement` | Intrusion | P1/P2 |
| `ddos` | DoS | P2/P3 |
| `brute_force` | Credential Attack | P2/P3/P4 |
| `phishing_reported` | Phishing | P2/P3/P4 |
| `port_scan` | Reconnaissance | P4 |
| `credential_stuffing` | Credential Attack | P2/P3 |

---

## Referințe

- [NIST SP 800-61r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) — Computer Security Incident Handling Guide
- [SANS Incident Response Process](https://www.sans.org/white-papers/incident-handlers-handbook/)
- [GDPR Breach Notification (Art. 33)](https://gdpr-info.eu/art-33-gdpr/) — 72 ore pentru notificare autoritate
