from collections import defaultdict
import time

# In-memory flow table keyed by source/destination IP, ports, and protocol.
flows = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "start_time": None,
    "last_seen": None,
    "capture_time": None,
    "syn_count": 0,
    "ack_count": 0,
    "fin_count": 0,
    "rst_count": 0
})

PROTOCOL_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
}

def make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    if (src_ip, src_port) <= (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    else:
        return (dst_ip, src_ip, dst_port, src_port, protocol)

def get_flow_features():
    feature_list = []

    for flow_key, flow in flows.items():
        protocol = flow_key[4]
        protocol_value = PROTOCOL_MAP.get(str(protocol).upper(), protocol)

        # The current Isolation Forest was trained on TCP/UDP live-flow features.
        if protocol_value not in [6, 17]:
            continue

        if flow["start_time"] is None or flow["last_seen"] is None:
            duration = 0.0
        else:
            duration = max(
             flow["last_seen"] - flow["start_time"],
              0.001)

        avg_packet_size = (
            flow["byte_count"] / flow["packet_count"]
            if flow["packet_count"] > 0
            else 0
        )

        packets_per_second = (
            flow["packet_count"] / duration
            if duration > 0
            else flow["packet_count"]
        )

        bytes_per_second = (
            flow["byte_count"] / duration
            if duration > 0
            else flow["byte_count"]
        )

        syn_ratio = (
            flow["syn_count"] / flow["packet_count"]
            if flow["packet_count"] > 0
            else 0
        )

        feature_list.append({
            "src_ip": flow_key[0],
            "dst_ip": flow_key[1],
            "src_port": flow_key[2],
            "dst_port": flow_key[3],
            "protocol": protocol_value,
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            "duration": duration,
            "capture_time": flow["capture_time"],
            "avg_packet_size": avg_packet_size,
            "packets_per_second": packets_per_second,
            "syn_count": flow["syn_count"],
            "ack_count": flow["ack_count"],
            "fin_count": flow["fin_count"],
            "rst_count": flow["rst_count"],
            "syn_ratio": syn_ratio,
            "bytes_per_second": bytes_per_second,
        })

    return feature_list

def update_flow(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    packet_length,
    syn=False,
    ack=False,
    fin=False,
    rst=False,
    capture_time=None
):
    flow_key = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

    now = time.time()

    flow = flows[flow_key]

    flow["packet_count"] += 1
    flow["byte_count"] += packet_length

    if syn:
        flow["syn_count"] += 1

    if ack:
        flow["ack_count"] += 1

    if fin:
        flow["fin_count"] += 1

    if rst:
        flow["rst_count"] += 1

    if flow["start_time"] is None:
        flow["start_time"] = now

    flow["last_seen"] = now
    flow["capture_time"] = capture_time or time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(now)
    )
    return flow_key
