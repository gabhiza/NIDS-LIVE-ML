# 🛡️ Network Intrusion Detection System (NIDS Live ML)

## Project Overview

A Python-based network security system that captures live traffic, extracts flow-level features, and runs dual-model anomaly detection in real time. The system combines an unsupervised Isolation Forest with a supervised Random Forest classifier, surfacing results through a Flask monitoring dashboard.

---

## Why This Project Matters

Network intrusion detection is a critical layer of defense for any infrastructure. This system:

* Detects anomalous traffic patterns the moment they appear, not after the fact
* Classifies threat types so responders know what they're dealing with
* Operates on live packet captures without requiring pre-labelled data for the anomaly layer
* Provides a lightweight, self-contained setup that runs locally without cloud dependencies
* Logs all detections persistently for post-incident review

---

## Data & Models

### Training Data

The Random Forest classifier is trained on the **NSL-KDD** dataset (`data/raw/KDDTrain+.txt`), a widely used benchmark for network intrusion research.

### Threat Buckets

| Label | Description |
| ----- | ----------- |
| normal | Legitimate traffic |
| ddos | Distributed denial-of-service |
| portscan | Reconnaissance scanning |
| brute_force | Credential stuffing / login attacks |
| web_attack | HTTP-layer exploits |
| privilege_escalation | Post-compromise lateral movement |
| other_attack | Uncategorised malicious activity |

### Live Flow Features

Extracted per-flow by the packet sniffer and written to `data/processed/live_flows.csv` for model consumption.

---

## Modeling Approach

### Anomaly Detection — Isolation Forest

* Unsupervised model, no labels required
* Scores each flow on how isolated it is from normal behaviour
* Outputs a continuous anomaly score surfaced in the dashboard

### Threat Classification — Random Forest

* Supervised classifier trained on NSL-KDD threat buckets
* Predicts the attack category (or normal) for each incoming flow
* Retrained on demand via `scripts/train_rf.py`

### Dual-Model Design

Running both models simultaneously gives two independent signals: the Isolation Forest catches unknown or novel anomalies while the Random Forest provides labelled context for known attack patterns.

---

## Dashboard

A Flask web interface at `http://127.0.0.1:5000` with four panels:

| Panel | What It Shows |
| ----- | ------------- |
| Live Alerts | Normal / attack status, timestamp, source IP, destination IP |
| Traffic Stats | Packets per second and number of active flows |
| Model Output | Random Forest prediction and Isolation Forest anomaly score |
| Logs | Recent detections pulled from `logs/anomalies.csv` |

---

## Project Structure

```text
NIDS-Live-ML/
|-- live/
|   |-- realtime_detector.py      # Packet sniffer and live detection loop
|   └── packet_sniffer.py         # Raw packet capture and flow export
|-- dashboard/
|   |-- app.py                    # Flask dashboard application
|   └── templates/                # HTML templates for dashboard views
|-- scripts/
|   └── train_rf.py               # Random Forest retraining script
|-- models/
|   |-- isolation_forest.pkl      # Trained Isolation Forest model
|   |-- iso_model.pkl             # Isolation Forest variant 
|   |-- preprocessor.pkl          # Feature scaler and preprocessor
|   └── rf_model.pkl              # Trained Random Forest classifier
|-- data/
|   |-- raw/
|   |   └── KDDTrain+.txt         # NSL-KDD training data
|   └── processed/
|       └── live_flows.csv        # Live flow features written by sniffer
|-- logs/
|   |-- anomalies.csv             # Persistent attack detection log
|   └── model_disagreements.csv   # Flows where RF and Isolation Forest diverge
└── requirements.txt
```

---

## How to Run

### Installation

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

> The packet sniffer uses `scapy` for raw packet capture — not the unrelated web-scraping library `Scrapy`.

### Start the Live Detector

```powershell
.\venv\Scripts\python.exe live\realtime_detector.py
```

### Start the Dashboard

```powershell
.\venv\Scripts\python.exe dashboard\app.py
```

Then open `http://127.0.0.1:5000` in your browser.

### Retrain the Random Forest

If you update the training data or want to adjust hyperparameters:

```powershell
.\venv\Scripts\python.exe scripts\train_rf.py
```

`KDDTrain+.txt` must be populated before running this. If the file is empty, training exits with a clear error message.

---

## Future Improvements

### Detection Enhancements

* Add LSTM-based sequence modelling to catch slow-burn intrusions spread across time
* Incorporate packet payload inspection for deeper protocol analysis
* Explore ensemble stacking of Isolation Forest and RF scores for a unified confidence metric

### Operational Features

* Real-time alerting via email or Slack on high-confidence detections
* Automated threat report generation at configurable intervals
* PCAP export of flagged flows for forensic follow-up

### Scalability

* Docker containerisation for easier deployment
* Support for distributed capture agents feeding a central detection node
* Database backend to replace CSV logging for larger traffic volumes
