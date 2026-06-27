# NIDS Live ML

Python-based Network Intrusion Detection System with packet sniffing, flow feature export, live Isolation Forest anomaly detection, Random Forest model output, and a Flask dashboard.

## Setup

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run The Live Detector

```powershell
.\venv\Scripts\python.exe live\realtime_detector.py
```

## Run The Dashboard

```powershell
.\venv\Scripts\python.exe dashboard\app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Dashboard Panels

- Live Alerts: normal or attack status, timestamp, source IP, destination IP.
- Traffic Stats: packets per second and number of flows.
- Model Output: Random Forest prediction and Isolation Forest anomaly score.
- Logs: recent attack detections from `logs/anomalies.csv`.

## Data Files

- `data/processed/live_flows.csv`: live flow features exported by the sniffer.
- `logs/anomalies.csv`: attack detections written by the dashboard backend.

## Notes

The packet sniffer uses `scapy`, not the unrelated web-scraping package `Scrapy`.

## Train RF Threat Buckets

The Random Forest can be retrained as a supervised threat-bucket classifier:

```powershell
.\venv\Scripts\python.exe scripts\train_rf.py
```

Bucket labels include `normal`, `ddos`, `portscan`, `brute_force`, `web_attack`, `privilege_escalation`, and `other_attack`.

This requires `data/raw/KDDTrain+.txt` to contain the NSL-KDD training data. If that file is empty, training stops with a clear error.
