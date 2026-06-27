import pandas as pd

FEATURE_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration",
    "capture_time",
    "avg_packet_size",
    "packets_per_second",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "bytes_per_second",
]

def export_to_csv(features, filename):

    df = pd.DataFrame(features, columns=FEATURE_COLUMNS)

    from pathlib import Path
    Path(filename).parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(filename, index=False)

    print(f"Saved {len(df)} flows to {filename}")
