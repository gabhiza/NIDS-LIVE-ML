from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAIN_FILE = PROJECT_ROOT / "data" / "raw" / "KDDTrain+.txt"
MODELS_DIR = PROJECT_ROOT / "models"
REPORT_FILE = MODELS_DIR / "rf_training_report.txt"

NSL_KDD_COLUMNS = [
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
    "label",
    "difficulty",
]

DDOS_LABELS = {
    "apache2",
    "back",
    "land",
    "mailbomb",
    "neptune",
    "pod",
    "processtable",
    "smurf",
    "teardrop",
    "udpstorm",
}

PORTSCAN_LABELS = {
    "ipsweep",
    "mscan",
    "nmap",
    "portsweep",
    "saint",
    "satan",
}

BRUTE_FORCE_LABELS = {
    "ftp_write",
    "guess_passwd",
    "imap",
    "multihop",
    "phf",
    "spy",
    "warezclient",
    "warezmaster",
    "xlock",
    "xsnoop",
}

WEB_ATTACK_LABELS = {
    "httptunnel",
    "named",
    "sendmail",
    "snmpgetattack",
    "snmpguess",
    "worm",
    "xterm",
}

PRIVILEGE_LABELS = {
    "buffer_overflow",
    "loadmodule",
    "perl",
    "ps",
    "rootkit",
    "sqlattack",
}


def threat_bucket(label):
    clean = str(label).strip().strip(".").lower()
    if clean == "normal":
        return "normal"
    if clean in DDOS_LABELS:
        return "ddos"
    if clean in PORTSCAN_LABELS:
        return "portscan"
    if clean in BRUTE_FORCE_LABELS:
        return "brute_force"
    if clean in WEB_ATTACK_LABELS:
        return "web_attack"
    if clean in PRIVILEGE_LABELS:
        return "privilege_escalation"
    return "other_attack"


def load_training_data():
    if not TRAIN_FILE.exists() or TRAIN_FILE.stat().st_size == 0:
        raise FileNotFoundError(
            f"Training data is missing or empty: {TRAIN_FILE}. "
            "Restore KDDTrain+.txt before training the bucket RF model."
        )

    df = pd.read_csv(TRAIN_FILE, header=None, names=NSL_KDD_COLUMNS)
    df["threat_bucket"] = df["label"].apply(threat_bucket)
    return df.drop(columns=["label", "difficulty"])


def main():
    df = load_training_data()
    x = df.drop(columns=["threat_bucket"])
    y = df["threat_bucket"]

    categorical_features = ["protocol_type", "service", "flag"]
    numerical_features = [column for column in x.columns if column not in categorical_features]

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numerical_features),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
        ]
    )

    x_train, x_val, y_train, y_val = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    x_train_processed = preprocessor.fit_transform(x_train)
    x_val_processed = preprocessor.transform(x_val)

    rf = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    rf.fit(x_train_processed, y_train)

    y_pred = rf.predict(x_val_processed)
    accuracy = accuracy_score(y_val, y_pred)
    report = classification_report(y_val, y_pred)
    matrix = confusion_matrix(y_val, y_pred, labels=list(rf.classes_))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, MODELS_DIR / "rf_model.pkl")
    joblib.dump(preprocessor, MODELS_DIR / "preprocessor.pkl")

    REPORT_FILE.write_text(
        "\n".join(
            [
                f"Accuracy: {accuracy}",
                "",
                "Classes:",
                ", ".join(map(str, rf.classes_)),
                "",
                "Classification report:",
                report,
                "",
                "Confusion matrix labels:",
                ", ".join(map(str, rf.classes_)),
                "",
                "Confusion matrix:",
                str(matrix),
            ]
        ),
        encoding="utf-8",
    )

    print(f"Saved bucket RF model to {MODELS_DIR / 'rf_model.pkl'}")
    print(f"Saved preprocessor to {MODELS_DIR / 'preprocessor.pkl'}")
    print(f"Saved report to {REPORT_FILE}")
    print(f"Accuracy: {accuracy}")
    print(f"Classes: {', '.join(map(str, rf.classes_))}")


if __name__ == "__main__":
    main()
