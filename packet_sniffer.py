# This is a simple packet sniffer that captures packets for 30 seconds and updates the flow information using the `update_flow` function from the `flow_builder` module. It prints a summary of each captured packet and, after the sniffing is complete, it prints the total number of flows and details of the first 5 flows.
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

import src.features.flow_builder as fb
print("FLOW IMPORTED:", id(fb.flows))
# The `update_flow` function is responsible for updating the flow information based on the captured packets. The `flows` dictionary stores the flow information, which can be printed after the sniffing is complete.
from scapy.all import sniff, IFACES
from scapy.layers.inet import IP, TCP, UDP
from live.realtime_detector import predict_flow
print("About to start sniffing...")

print("Sniffer starting...")

def packet_callback(packet):
    print("CALLBACK TRIGGERED")
    
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    else:
        protocol = str(packet[IP].proto)

    src_port = 0
    dst_port = 0
    syn = False
    ack = False
    fin = False
    rst = False

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        flags = packet[TCP].flags
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

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
        rst=rst
    )
    print(packet.summary())
    print("Sniff completed")

# verifying if the packet capture is working
from scapy.all import sniff

iface_name = "Ethernet"

selected_iface = None
for iface in IFACES.values():
    if iface.name == iface_name:
        selected_iface = iface.name
        break

if selected_iface is None:
    print(f"Interface '{iface_name}' not found. Available interfaces:")
    for iface in IFACES.values():
        print(f" - {iface.name}")
    raise SystemExit("Please choose a valid interface from the available list.")

print(f"Using interface: {selected_iface}")

sniff(
    iface=selected_iface,
    filter="ip or tcp or udp",
    prn=packet_callback,
    store=False,
    timeout=10
)
# After sniffing is complete, print the total number of flows and details of the first 5 flows.
print(len(fb.flows))

for key, value in list(fb.flows.items())[:5]:
    print(key)
    print(value)

print("BEFORE FEATURE EXTRACTION FLOWS:", len(fb.flows))

features = fb.get_flow_features()
print("\nRunning anomaly detection...\n")

for flow in features:

    result = predict_flow(flow)

    if result == -1:

        print(
            f"[ALERT] Suspicious Flow: "
            f"{flow['src_ip']} -> {flow['dst_ip']}"
        )

# The `export_to_csv` function is responsible for exporting the flow features to a CSV file. It takes the list of features and the filename as input parameters, creates a DataFrame using pandas, and saves it to a CSV file without the index. The function also prints a message indicating how many flows were saved and the filename.
from src.features.export_features import export_to_csv
print("FEATURE COUNT:", len(features))
print("FLOWS COUNT:", len(fb.flows))
export_to_csv(
    features,
    os.path.join(project_root, "data", "processed", "live_flows.csv")
)
# print the generated ml features for the first 5 flows
print("\nGenerated Features:")
print("FEATURE OUTPUT:", len(features))
for row in features[:5]:
    print(row)