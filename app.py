import csv
import json
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, Response, jsonify, render_template, request, send_file
from scapy.all import IFACES, sniff
from scapy.layers.inet import IP, TCP, UDP


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from src.features import flow_builder as fb
from src.features.export_features import export_to_csv


LIVE_FLOWS_CSV = PROJECT_ROOT / "data" / "processed" / "live_flows.csv"
ANOMALIES_CSV = PROJECT_ROOT / "logs" / "anomalies.csv"
DISAGREEMENTS_CSV = PROJECT_ROOT / "logs" / "model_disagreements.csv"
MODELS_DIR = PROJECT_ROOT / "models"
TRAIN_NOTEBOOK = PROJECT_ROOT / "src" / "dataset" / "load_data.ipynb"
REPORT_FILE = MODELS_DIR / "rf_training_report.txt"
RAW_TRAIN = PROJECT_ROOT / "data" / "raw" / "KDDTrain+.txt"
RAW_TEST = PROJECT_ROOT / "data" / "raw" / "KDDTest+.txt"
PCAP_DIRS = [PROJECT_ROOT / "pcaps", PROJECT_ROOT / "data" / "pcaps", PROJECT_ROOT / "captures"]

ISO_FEATURE_COLUMNS = [
    "src_port",
    "dst_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration",
    "avg_packet_size",
    "packets_per_second",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "bytes_per_second",
]

RF_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

LOG_COLUMNS = [
    "timestamp",
    "status",
    "severity",
    "attack_type",
    "confidence",
    "confidence_score",
    "detection_source",
    "model_trigger",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "rf_prediction",
    "iso_prediction",
    "iso_score",
    "packets_per_second",
    "flow_summary",
    "flow_key",
]

DISAGREEMENT_COLUMNS = [
    "timestamp",
    "anomaly_score",
    "rf_prediction",
    "iso_prediction",
    "flow_summary",
    "flow_key",
]

PROTOCOL_TO_NAME = {
    1: "icmp",
    6: "tcp",
    17: "udp",
}

PORT_TO_SERVICE = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain_u",
    80: "http",
    110: "pop_3",
    143: "imap4",
    443: "http",
}

app = Flask(__name__, template_folder="templates")

_iso_model = None
_rf_model = None
_preprocessor = None
_capture_thread = None
_capture_lock = threading.Lock()
_state_lock = threading.Lock()
_recent_detections = deque(maxlen=100)
_capture_state = {
    "running": False,
    "status": "Stopped",
    "interface": None,
    "packets_seen": 0,
    "last_packet_time": None,
    "error": None,
}
_training_cache = None
_traffic_history = deque(maxlen=120)
_feature_baseline = None


def _load_models():
    global _iso_model, _rf_model, _preprocessor
    if _iso_model is None:
        iso_candidates = [
            MODELS_DIR / "iso_model.pkl",
            MODELS_DIR / "isolation_forest.pkl",
            PROJECT_ROOT / "src" / "training" / "models" / "models" / "isolation_forest.pkl",
        ]
        iso_path = next((path for path in iso_candidates if path.exists()), None)
        if iso_path is None:
            raise FileNotFoundError("Isolation Forest model not found in models/")
        _iso_model = joblib.load(iso_path)
    if _rf_model is None:
        rf_path = MODELS_DIR / "rf_model.pkl"
        if not rf_path.exists():
            raise FileNotFoundError(f"Random Forest model not found: {rf_path}")
        _rf_model = joblib.load(rf_path)
    if _preprocessor is None:
        preprocessor_path = MODELS_DIR / "preprocessor.pkl"
        if not preprocessor_path.exists():
            raise FileNotFoundError(f"RF preprocessor not found: {preprocessor_path}")
        _preprocessor = joblib.load(preprocessor_path)
    return _iso_model, _rf_model, _preprocessor


def _ensure_csv_log(path, columns):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.stat().st_size == 0:
        with path.open("w", newline="", encoding="utf-8") as file:
            csv.DictWriter(file, fieldnames=columns).writeheader()
        return

    try:
        df = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        with path.open("w", newline="", encoding="utf-8") as file:
            csv.DictWriter(file, fieldnames=columns).writeheader()
        return
    except pd.errors.ParserError:
        backup = path.with_suffix(f".{int(time.time())}.bak")
        path.replace(backup)
        with path.open("w", newline="", encoding="utf-8") as file:
            csv.DictWriter(file, fieldnames=columns).writeheader()
        return

    changed = False
    for column in columns:
        if column not in df.columns:
            df[column] = ""
            changed = True
    extra_columns = [column for column in df.columns if column not in columns]
    if changed or extra_columns:
        df = df[columns + extra_columns]
        df.to_csv(path, index=False)


def _ensure_anomaly_log():
    _ensure_csv_log(ANOMALIES_CSV, LOG_COLUMNS)


def _ensure_disagreement_log():
    _ensure_csv_log(DISAGREEMENTS_CSV, DISAGREEMENT_COLUMNS)


def _protocol_number(value):
    text = str(value).strip().upper()
    if text == "TCP":
        return 6
    if text == "UDP":
        return 17
    if text == "ICMP":
        return 1
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _flow_key(flow):
    return "|".join(
        str(flow.get(column, ""))
        for column in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    )


def _service_from_port(dst_port):
    try:
        return PORT_TO_SERVICE.get(int(float(dst_port)), "other")
    except (TypeError, ValueError):
        return "other"


def _flag_from_flow(flow):
    if float(flow.get("rst_count", 0) or 0) > 0:
        return "REJ"
    if float(flow.get("syn_count", 0) or 0) > 0 and float(flow.get("ack_count", 0) or 0) == 0:
        return "S0"
    return "SF"


def _rf_input_from_flow(flow):
    protocol = _protocol_number(flow.get("protocol", 0))
    packet_count = float(flow.get("packet_count", 0) or 0)
    row = {column: 0 for column in RF_COLUMNS}
    row.update(
        {
            "duration": float(flow.get("duration", 0) or 0),
            "protocol_type": PROTOCOL_TO_NAME.get(protocol, "tcp"),
            "service": _service_from_port(flow.get("dst_port", 0)),
            "flag": _flag_from_flow(flow),
            "src_bytes": float(flow.get("byte_count", 0) or 0),
            "dst_bytes": 0,
            "logged_in": 1 if protocol == 6 and float(flow.get("ack_count", 0) or 0) > 0 else 0,
            "count": packet_count,
            "srv_count": packet_count,
            "same_srv_rate": 1.0,
            "dst_host_count": 1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0,
        }
    )
    return pd.DataFrame([row], columns=RF_COLUMNS)


def _iso_input_from_flow(flow, iso_model):
    row = dict(flow)
    row["protocol"] = _protocol_number(row.get("protocol", 0))
    expected = list(getattr(iso_model, "feature_names_in_", ISO_FEATURE_COLUMNS))
    df = pd.DataFrame([row]).reindex(columns=expected, fill_value=0)
    return df.apply(pd.to_numeric, errors="coerce").fillna(0)


def _prediction_label(value):
    text = str(value).strip().strip(".").lower()
    if text in {"0", "normal"}:
        return "Normal"
    if text in {"1", "attack", "anomaly", "malicious"}:
        return "Attack"
    label_map = {
        "ddos": "DoS",
        "dos": "DoS",
        "portscan": "Probe",
        "probe": "Probe",
        "brute_force": "R2L",
        "web_attack": "R2L",
        "privilege_escalation": "U2R",
        "r2l": "R2L",
        "u2r": "U2R",
        "other_attack": "Attack",
    }
    return label_map.get(text, text.replace("_", " ").title())


def _is_normal_label(value):
    return _prediction_label(value) == "Normal"


def _rf_confidence(rf_model, rf_processed, rf_prediction):
    if not hasattr(rf_model, "predict_proba"):
        return 0.5
    try:
        probabilities = rf_model.predict_proba(rf_processed)[0]
        classes = list(getattr(rf_model, "classes_", []))
        if rf_prediction in classes:
            return float(probabilities[classes.index(rf_prediction)])
        return float(max(probabilities))
    except Exception:
        return 0.5


def _iso_confidence(score, iso_prediction):
    if iso_prediction == -1:
        return min(0.99, max(0.5, 0.5 + abs(float(score))))
    return min(0.99, max(0.5, 0.65 + float(score)))


def _attack_type_from_flow(flow, rf_label, iso_prediction):
    if rf_label in {"DoS", "Probe", "R2L", "U2R"}:
        return rf_label
    if rf_label == "Normal" and iso_prediction != -1:
        return "Normal"

    dst_port = int(float(flow.get("dst_port", 0) or 0))
    packet_count = float(flow.get("packet_count", 0) or 0)
    packets_per_second = float(flow.get("packets_per_second", 0) or 0)
    bytes_per_second = float(flow.get("bytes_per_second", 0) or 0)
    syn_count = float(flow.get("syn_count", 0) or 0)
    ack_count = float(flow.get("ack_count", 0) or 0)
    rst_count = float(flow.get("rst_count", 0) or 0)

    if packet_count >= 1000 or packets_per_second >= 250 or bytes_per_second >= 100000:
        return "DoS"
    if syn_count > 0 and ack_count == 0 or rst_count > 0:
        return "Probe"
    if dst_port in {21, 22, 23, 25, 110, 143, 389, 445, 3389}:
        return "R2L"
    if dst_port in {512, 513, 514, 2049}:
        return "U2R"
    if iso_prediction == -1 and rf_label == "Normal":
        return "Anomaly"
    return "Probe"


def _severity_for_detection(attack_type, confidence, disagreement, flow):
    if attack_type == "Normal":
        return "Low"
    if disagreement:
        return "High"
    packets_per_second = float(flow.get("packets_per_second", 0) or 0)
    if attack_type in {"U2R", "DoS"} and (confidence >= 0.85 or packets_per_second >= 250):
        return "Critical"
    if attack_type in {"DoS", "R2L", "U2R", "Attack"}:
        return "High"
    if attack_type in {"Probe", "Anomaly"}:
        return "Medium"
    return "Low"


def _flow_summary(flow):
    return (
        f"{flow.get('src_ip', '')}:{flow.get('src_port', '')} -> "
        f"{flow.get('dst_ip', '')}:{flow.get('dst_port', '')} "
        f"proto={_protocol_number(flow.get('protocol', 0))} "
        f"packets={flow.get('packet_count', 0)} bytes={flow.get('byte_count', 0)}"
    )


def _firewall_rule_for_source(src_ip):
    if not src_ip:
        return ""
    return (
        'netsh advfirewall firewall add rule name="Block_Malicious_IP" '
        f"dir=in action=block remoteip={src_ip}"
    )


def _logged_flow_keys():
    _ensure_anomaly_log()
    try:
        df = pd.read_csv(ANOMALIES_CSV)
    except pd.errors.EmptyDataError:
        return set()
    if "flow_key" not in df.columns:
        return set()
    return set(df["flow_key"].dropna().astype(str))


def _append_anomalies(rows):
    if not rows:
        return
    _ensure_anomaly_log()
    existing = _logged_flow_keys()
    with ANOMALIES_CSV.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=LOG_COLUMNS)
        for row in rows:
            if row["flow_key"] in existing:
                continue
            writer.writerow({column: row.get(column, "") for column in LOG_COLUMNS})
            existing.add(row["flow_key"])


def _append_disagreements(rows):
    disagreement_rows = [row for row in rows if row.get("model_disagreement")]
    if not disagreement_rows:
        return
    _ensure_disagreement_log()
    existing = _logged_disagreement_keys()
    with DISAGREEMENTS_CSV.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=DISAGREEMENT_COLUMNS)
        for row in disagreement_rows:
            if row["flow_key"] in existing:
                continue
            writer.writerow(
                {
                    "timestamp": row.get("timestamp", ""),
                    "anomaly_score": row.get("iso_score", ""),
                    "rf_prediction": row.get("rf_prediction", ""),
                    "iso_prediction": row.get("iso_prediction", ""),
                    "flow_summary": row.get("flow_summary", ""),
                    "flow_key": row.get("flow_key", ""),
                }
            )
            existing.add(row["flow_key"])


def _logged_disagreement_keys():
    _ensure_disagreement_log()
    try:
        df = pd.read_csv(DISAGREEMENTS_CSV)
    except pd.errors.EmptyDataError:
        return set()
    if "flow_key" not in df.columns:
        return set()
    return set(df["flow_key"].dropna().astype(str))


def _recent_logs(limit=20):
    _ensure_anomaly_log()
    try:
        df = pd.read_csv(ANOMALIES_CSV)
    except pd.errors.EmptyDataError:
        return []
    if df.empty:
        return []
    rows = df.tail(limit).iloc[::-1].fillna("").to_dict(orient="records")
    for row in rows:
        if not row.get("attack_type"):
            row["attack_type"] = "Anomaly" if row.get("iso_prediction") == "Anomaly" else _prediction_label(row.get("rf_prediction", "Attack"))
        if not row.get("severity"):
            row["severity"] = "Medium" if row.get("status") != "Normal" else "Low"
        if not row.get("confidence_score"):
            confidence = row.get("confidence")
            try:
                row["confidence_score"] = f"{round(float(confidence) * 100, 1)}%"
            except (TypeError, ValueError):
                row["confidence_score"] = "N/A"
        if not row.get("model_trigger"):
            row["model_trigger"] = "Historical log"
        if not row.get("detection_source"):
            row["detection_source"] = "Historical log"
    return rows


def _recent_disagreements(limit=20):
    _ensure_disagreement_log()
    try:
        df = pd.read_csv(DISAGREEMENTS_CSV)
    except pd.errors.EmptyDataError:
        return []
    if df.empty:
        return []
    return df.tail(limit).iloc[::-1].fillna("").to_dict(orient="records")


def _alert_rows(detections, recent_detections, logs=None):
    logs = logs or []
    rows = [
        row
        for row in list(detections) + list(recent_detections) + list(logs)
        if row.get("status") != "Normal"
    ]
    seen = set()
    unique_rows = []
    for row in rows:
        key = row.get("flow_key")
        if key in seen:
            continue
        seen.add(key)
        unique_rows.append(row)
    return sorted(unique_rows, key=lambda row: row.get("timestamp", ""), reverse=True)


def _priority_banner(alerts):
    grouped = {severity: [] for severity in ["Critical", "High", "Medium", "Low"]}
    for row in alerts:
        severity = row.get("severity", "Low")
        grouped.setdefault(severity, []).append(row)
    return {
        severity: {
            "count": len(rows),
            "items": rows[:4],
        }
        for severity, rows in grouped.items()
    }


def _latest_classification(detections, recent_detections):
    rows = list(detections) or list(recent_detections)
    if not rows:
        return {
            "attack_type": "Normal",
            "confidence": "N/A",
            "detection_source": "No live flow",
        }
    latest = rows[-1] if detections else rows[0]
    return {
        "attack_type": latest.get("attack_type", "Normal"),
        "confidence": latest.get("confidence_score", "N/A"),
        "detection_source": latest.get("detection_source", "N/A"),
        "rf_prediction": latest.get("rf_prediction", "N/A"),
        "iso_prediction": latest.get("iso_prediction", "N/A"),
    }


def _record_chart_point(detections):
    now = datetime.now().strftime("%H:%M:%S")
    packets_per_second = round(sum(row.get("packets_per_second", 0) for row in detections), 3)
    attacks = sum(1 for row in detections if row.get("status") != "Normal")
    anomaly_scores = [
        float(row.get("iso_score", 0) or 0)
        for row in detections
        if row.get("iso_score") not in {"", None}
    ]
    _traffic_history.append(
        {
            "timestamp": now,
            "packets_per_second": packets_per_second,
            "flows_per_second": len(detections),
            "attacks": attacks,
            "avg_anomaly_score": round(sum(anomaly_scores) / len(anomaly_scores), 6)
            if anomaly_scores
            else 0,
        }
    )


def _chart_data():
    history = list(_traffic_history)
    return {
        "timestamps": [row["timestamp"] for row in history],
        "packets_per_second": [row["packets_per_second"] for row in history],
        "flows_per_second": [row["flows_per_second"] for row in history],
        "attacks": [row["attacks"] for row in history],
        "anomaly_scores": [row["avg_anomaly_score"] for row in history],
    }


def _drift_monitor(detections):
    global _feature_baseline
    total = len(detections)
    if total == 0:
        return {
            "status": "GREEN",
            "label": "Stable",
            "anomaly_rate": 0,
            "prediction_distribution": {},
            "model_disagreement_frequency": 0,
            "feature_distribution_shift": 0,
        }

    anomaly_count = sum(1 for row in detections if row.get("iso_prediction") == "Anomaly")
    disagreement_count = sum(1 for row in detections if row.get("model_disagreement"))
    distribution = {}
    for row in detections:
        attack_type = row.get("attack_type", "Normal")
        distribution[attack_type] = distribution.get(attack_type, 0) + 1

    feature_now = {
        "avg_packet_size": sum(row.get("byte_count", 0) / max(row.get("packet_count", 1), 1) for row in detections) / total,
        "packets_per_second": sum(row.get("packets_per_second", 0) for row in detections) / total,
    }
    if _feature_baseline is None:
        _feature_baseline = dict(feature_now)

    shifts = []
    for key, value in feature_now.items():
        baseline = max(abs(float(_feature_baseline.get(key, 0))), 1.0)
        shifts.append(abs(float(value) - float(_feature_baseline.get(key, 0))) / baseline)
        _feature_baseline[key] = (_feature_baseline[key] * 0.95) + (float(value) * 0.05)
    feature_shift = round(max(shifts), 4) if shifts else 0

    anomaly_rate = anomaly_count / total
    disagreement_frequency = disagreement_count / total
    if anomaly_rate >= 0.5 or disagreement_frequency >= 0.25 or feature_shift >= 1.0:
        status = "RED"
        label = "Significant Drift"
    elif anomaly_rate >= 0.2 or disagreement_frequency >= 0.1 or feature_shift >= 0.5:
        status = "YELLOW"
        label = "Possible Drift"
    else:
        status = "GREEN"
        label = "Stable"

    return {
        "status": status,
        "label": label,
        "anomaly_rate": round(anomaly_rate, 4),
        "prediction_distribution": distribution,
        "model_disagreement_frequency": round(disagreement_frequency, 4),
        "feature_distribution_shift": feature_shift,
    }


def _pcap_files():
    files = []
    for folder in PCAP_DIRS:
        if not folder.exists():
            continue
        for path in folder.glob("*.pcap*"):
            files.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    return files


def _pcap_support():
    files = _pcap_files()
    return {
        "implemented": bool(files),
        "files": files[:10],
        "message": "PCAP files can be downloaded when placed in pcaps/, data/pcaps/, or captures/.",
    }


def _predict_flow(flow):
    iso_model, rf_model, preprocessor = _load_models()
    iso_input = _iso_input_from_flow(flow, iso_model)
    rf_input = _rf_input_from_flow(flow)
    rf_processed = preprocessor.transform(rf_input)

    iso_prediction = int(iso_model.predict(iso_input)[0])
    iso_score = float(iso_model.score_samples(iso_input)[0])
    rf_prediction = rf_model.predict(rf_processed)[0]
    rf_label = _prediction_label(rf_prediction)
    rf_confidence = _rf_confidence(rf_model, rf_processed, rf_prediction)
    iso_confidence = _iso_confidence(iso_score, iso_prediction)
    disagreement = _is_normal_label(rf_prediction) != (iso_prediction != -1)
    attack_type = _attack_type_from_flow(flow, rf_label, iso_prediction)
    confidence = max(rf_confidence, iso_confidence if iso_prediction == -1 else 0)
    severity = _severity_for_detection(attack_type, confidence, disagreement, flow)

    if disagreement:
        status = "MODEL DISAGREEMENT DETECTED"
        model_trigger = "Random Forest / Isolation Forest disagreement"
        detection_source = "RF + Isolation Forest"
    elif iso_prediction == -1 or rf_label != "Normal":
        status = "Attack detected"
        model_trigger = "Isolation Forest" if iso_prediction == -1 else "Random Forest"
        detection_source = "Isolation Forest" if iso_prediction == -1 else "Random Forest"
    else:
        status = "Normal"
        model_trigger = "No alert"
        detection_source = "RF + Isolation Forest"

    src_ip = str(flow.get("src_ip", ""))

    return {
        "timestamp": flow.get("capture_time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "severity": severity,
        "attack_type": attack_type,
        "confidence": round(float(confidence), 4),
        "confidence_score": f"{round(float(confidence) * 100, 1)}%",
        "detection_source": detection_source,
        "model_trigger": model_trigger,
        "src_ip": src_ip,
        "dst_ip": str(flow.get("dst_ip", "")),
        "src_port": flow.get("src_port", ""),
        "dst_port": flow.get("dst_port", ""),
        "protocol": _protocol_number(flow.get("protocol", 0)),
        "packet_count": int(float(flow.get("packet_count", 0) or 0)),
        "byte_count": int(float(flow.get("byte_count", 0) or 0)),
        "duration": round(float(flow.get("duration", 0) or 0), 6),
        "rf_prediction": rf_label,
        "rf_raw_prediction": str(rf_prediction),
        "rf_alignment": "NSL-KDD mapped",
        "iso_prediction": "Anomaly" if iso_prediction == -1 else "Normal",
        "iso_raw_prediction": iso_prediction,
        "iso_score": round(iso_score, 6),
        "packets_per_second": round(float(flow.get("packets_per_second", 0) or 0), 3),
        "flow_summary": _flow_summary(flow),
        "firewall_rule": _firewall_rule_for_source(src_ip),
        "model_disagreement": disagreement,
        "flow_key": _flow_key(flow),
    }


def _flow_features_from_memory():
    with _capture_lock:
        return fb.get_flow_features()


def _record_detections(detections):
    anomaly_rows = [row for row in detections if row["status"] != "Normal"]
    _append_anomalies(anomaly_rows)
    _append_disagreements(detections)
    with _state_lock:
        for row in detections:
            existing_keys = {item["flow_key"] for item in _recent_detections}
            if row["flow_key"] not in existing_keys:
                _recent_detections.append(row)


def _update_live_csv_and_predictions():
    features = _flow_features_from_memory()
    if features or not LIVE_FLOWS_CSV.exists():
        export_to_csv(features, LIVE_FLOWS_CSV)
    detections = [_predict_flow(flow) for flow in features]
    _record_detections(detections)
    return detections


def _packet_callback(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = str(packet[IP].proto)
    src_port = 0
    dst_port = 0
    syn = False
    ack = False
    fin = False
    rst = False

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    capture_time = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S")
    with _capture_lock:
        fb.update_flow(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            len(packet),
            syn=syn,
            ack=ack,
            fin=fin,
            rst=rst,
            capture_time=capture_time,
        )

    with _state_lock:
        _capture_state["packets_seen"] += 1
        _capture_state["last_packet_time"] = capture_time
        _capture_state["status"] = "Capturing"


def _select_interface():
    requested = os.environ.get("NIDS_IFACE")
    if requested:
        return requested
    for iface in IFACES.values():
        if iface.name == "Ethernet":
            return iface.name
    for iface in IFACES.values():
        if iface.name:
            return iface.name
    return None


def _capture_loop():
    selected_iface = _select_interface()
    with _state_lock:
        _capture_state.update(
            {
                "running": True,
                "status": "Starting",
                "interface": selected_iface,
                "error": None,
            }
        )

    while True:
        try:
            sniff(
                iface=selected_iface,
                filter="ip or tcp or udp",
                prn=_packet_callback,
                store=False,
                timeout=2,
            )
            _update_live_csv_and_predictions()
            with _state_lock:
                _capture_state["status"] = "Capturing"
                _capture_state["running"] = True
                _capture_state["error"] = None
        except Exception as exc:
            with _state_lock:
                _capture_state["status"] = "Error"
                _capture_state["running"] = False
                _capture_state["error"] = str(exc)
            time.sleep(3)


def start_capture_thread():
    global _capture_thread
    if _capture_thread and _capture_thread.is_alive():
        return
    _capture_thread = threading.Thread(target=_capture_loop, daemon=True)
    _capture_thread.start()


def _file_summary(path):
    if not path.exists():
        return {"path": str(path), "status": "missing", "size_bytes": 0, "rows": 0}
    size = path.stat().st_size
    if size == 0:
        return {"path": str(path), "status": "empty", "size_bytes": 0, "rows": 0}
    try:
        rows = sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))
    except OSError:
        rows = None
    return {"path": str(path), "status": "available", "size_bytes": size, "rows": rows}


def _extract_training_history():
    global _training_cache
    if _training_cache is not None:
        return _training_cache

    summary = {
        "rf_accuracy": "saved notebook output not found",
        "rf_classes": "",
        "classification_report": "",
        "confusion_matrix": "",
    }
    if REPORT_FILE.exists():
        text = REPORT_FILE.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if line.startswith("Accuracy:"):
                summary["rf_accuracy"] = line.replace("Accuracy:", "").strip()
            elif line.startswith("Classes:"):
                summary["rf_classes"] = line.replace("Classes:", "").strip()
        summary["classification_report"] = text
        _training_cache = summary
        return summary

    if TRAIN_NOTEBOOK.exists():
        try:
            notebook = json.loads(TRAIN_NOTEBOOK.read_text(encoding="utf-8"))
            outputs = []
            for cell in notebook.get("cells", []):
                for output in cell.get("outputs", []):
                    text = "".join(output.get("text", []))
                    if text:
                        outputs.append(text.strip())
            for text in outputs:
                if text.startswith("Accuracy:"):
                    summary["rf_accuracy"] = text.replace("Accuracy:", "").strip()
                elif "precision" in text and "recall" in text and "f1-score" in text:
                    summary["classification_report"] = text
                elif text.startswith("[[") and "]]" in text:
                    summary["confusion_matrix"] = text
        except (OSError, json.JSONDecodeError):
            pass

    _training_cache = summary
    return summary


def _metadata():
    try:
        iso_model, rf_model, preprocessor = _load_models()
        model_info = {
            "rf_estimators": len(getattr(rf_model, "estimators_", [])),
            "rf_processed_features": int(getattr(rf_model, "n_features_in_", 0)),
            "rf_classes": [str(value) for value in getattr(rf_model, "classes_", [])],
            "rf_raw_features": list(getattr(preprocessor, "feature_names_in_", RF_COLUMNS)),
            "iso_estimators": len(getattr(iso_model, "estimators_", [])),
            "iso_features": list(getattr(iso_model, "feature_names_in_", ISO_FEATURE_COLUMNS)),
            "iso_contamination": getattr(iso_model, "contamination", ""),
        }
    except Exception as exc:
        model_info = {"error": str(exc)}

    return {
        "raw_dataset": {
            "train": _file_summary(RAW_TRAIN),
            "test": _file_summary(RAW_TEST),
        },
        "training_history": _extract_training_history(),
        "model_info": model_info,
        "rf_feature_alignment": {
            "status": "approximate",
            "message": (
                "RF bucket labels come from a supervised NSL-KDD model when retrained with "
                "scripts/train_rf.py. Live packet flows are mapped into the NSL-KDD schema "
                "where possible; for strongest reliability, extract true NSL-KDD-equivalent "
                "features from live traffic or retrain RF directly on live-flow features."
            ),
        },
    }


def build_dashboard_state():
    if os.environ.get("NIDS_DISABLE_CAPTURE") != "1":
        start_capture_thread()
    detections = _update_live_csv_and_predictions()
    _record_chart_point(detections)

    with _state_lock:
        capture_state = dict(_capture_state)
        recent_detections = list(_recent_detections)[-20:][::-1]

    recent_logs = _recent_logs()
    alerts = _alert_rows(detections, recent_detections, recent_logs)
    latest_alert = alerts[0] if alerts else (detections[-1] if detections else None)
    classification = _latest_classification(detections, recent_detections or alerts)
    pcap_support = _pcap_support()

    if not detections:
        return {
            "status": "Normal",
            "timestamp": capture_state.get("last_packet_time"),
            "latest_alert": latest_alert,
            "alert_priority": _priority_banner(alerts),
            "latest_classification": classification,
            "alert_queue": alerts,
            "incident_action": latest_alert,
            "packet_sniffer": capture_state,
            "flow_builder": {"active_flows": len(fb.flows), "features": []},
            "traffic": {"packets_per_second": 0, "number_of_flows": len(fb.flows)},
            "model_output": {"rf_prediction": "N/A", "iso_prediction": "N/A", "iso_score": "N/A"},
            "predictions": [],
            "recent_detections": recent_detections,
            "logs": recent_logs,
            "model_disagreements": _recent_disagreements(),
            "charts": _chart_data(),
            "drift_monitor": _drift_monitor(detections),
            "pcap_support": pcap_support,
            "metadata": _metadata(),
        }

    latest = detections[-1]
    normal_count = sum(1 for row in detections if row["status"] == "Normal")
    attack_count = sum(1 for row in detections if row["status"] == "Attack detected")
    disagreement_count = sum(1 for row in detections if row["status"] == "MODEL DISAGREEMENT DETECTED")
    return {
        "status": "Attack detected" if attack_count or disagreement_count else "Normal",
        "timestamp": latest["timestamp"],
        "latest_alert": latest_alert,
        "alert_priority": _priority_banner(alerts),
        "latest_classification": classification,
        "alert_queue": alerts,
        "incident_action": latest_alert,
        "packet_sniffer": capture_state,
        "flow_builder": {"active_flows": len(fb.flows), "features": _flow_features_from_memory()[-10:]},
        "traffic": {
            "packets_per_second": round(sum(row["packets_per_second"] for row in detections), 3),
            "number_of_flows": len(detections),
            "normal_flows": normal_count,
            "attack_flows": attack_count,
            "model_disagreements": disagreement_count,
        },
        "model_output": {
            "rf_prediction": latest["rf_prediction"],
            "rf_alignment": latest["rf_alignment"],
            "iso_prediction": latest["iso_prediction"],
            "iso_score": latest["iso_score"],
        },
        "predictions": detections,
        "recent_detections": recent_detections,
        "logs": recent_logs,
        "model_disagreements": _recent_disagreements(),
        "charts": _chart_data(),
        "drift_monitor": _drift_monitor(detections),
        "pcap_support": pcap_support,
        "metadata": _metadata(),
    }


@app.route("/")
def index():
    start_capture_thread()
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    try:
        return jsonify(build_dashboard_state())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/events")
def api_events():
    def stream():
        while True:
            try:
                yield f"data: {json.dumps(build_dashboard_state())}\n\n"
            except Exception as exc:
                yield f"data: {json.dumps({'error': str(exc)})}\n\n"
            time.sleep(2)

    return Response(stream(), mimetype="text/event-stream")


@app.route("/api/firewall-rule")
def api_firewall_rule():
    source_ip = request.args.get("source_ip", "")
    if not source_ip:
        state = build_dashboard_state()
        source_ip = (state.get("latest_alert") or {}).get("src_ip", "")
    return jsonify(
        {
            "source_ip": source_ip,
            "rule": _firewall_rule_for_source(source_ip),
            "note": "Recommendation only. The dashboard does not execute firewall changes.",
        }
    )


@app.route("/api/download-alert-details")
def api_download_alert_details():
    state = build_dashboard_state()
    alert = state.get("latest_alert") or {}
    payload = json.dumps(alert, indent=2)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=alert_details.json"},
    )


@app.route("/api/pcaps")
def api_pcaps():
    return jsonify(_pcap_support())


@app.route("/api/pcaps/<path:filename>")
def api_download_pcap(filename):
    for item in _pcap_files():
        path = Path(item["path"])
        if path.name == filename:
            return send_file(path, as_attachment=True)
    return jsonify({"error": "PCAP not found"}), 404


if __name__ == "__main__":
    start_capture_thread()
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=True,
        use_reloader=False,
        threaded=True,
    )
