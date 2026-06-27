import os

import joblib
import pandas as pd

_model_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
    "iso_model.pkl",
)
model = None

DEFAULT_FEATURE_COLUMNS = [
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

PROTOCOL_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
}


def _load_model():
    global model
    if model is None:
        if not os.path.exists(_model_path):
            raise FileNotFoundError(f"Model file not found: {_model_path}")
        model = joblib.load(_model_path)
    return model


#prediction function
def predict_flow(feature_dict):
    loaded_model = _load_model()

    df = pd.DataFrame([feature_dict])

    df = df.drop(
        columns=[
            "src_ip",
            "dst_ip"
        ],
        errors="ignore"
    )

    if "protocol" in df.columns:
        mapped = df["protocol"].astype(str).str.upper().map(PROTOCOL_MAP)
        df["protocol"] = mapped.where(mapped.notna(), df["protocol"])

    expected_columns = list(
        getattr(loaded_model, "feature_names_in_", DEFAULT_FEATURE_COLUMNS)
    )
    df = df.reindex(columns=expected_columns, fill_value=0)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

    prediction = loaded_model.predict(df)[0]

    return prediction

if __name__ == "__main__":

    sample = {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": 6,
        "packet_count": 10,
        "byte_count": 5000,
        "duration": 5,
        "avg_packet_size": 500,
        "packets_per_second": 2,
        "syn_count": 1,
        "ack_count": 9,
        "fin_count": 0,
        "rst_count": 0,
        "syn_ratio": 0.1,
        "bytes_per_second": 1000
    }

    print(predict_flow(sample))
