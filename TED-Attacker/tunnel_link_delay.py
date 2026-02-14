import csv
from collections import defaultdict
from itertools import combinations

# ------------------ Configuration ------------------
two_node_csv = "two-layer_delay_log.csv"  # Two-node RTT CSV (ms)
three_node_csv = "delay_results2.csv"     # Three-node RTT CSV (s)
output_csv = "all_pair_delays.csv"

# ---------------- Read Two-node RTT ----------------
host_tunnel_rtt = defaultdict(list)  # (host, tunnel) -> [delay_ms]

with open(two_node_csv, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        host = row["Send_Outer_Src"]
        tunnel = row["Node_Address"]
        delay = float(row["Delay_ms"])
        key = (host, tunnel)
        host_tunnel_rtt[key].append(delay)

# Average value
host_tunnel_avg = {k: sum(v)/len(v) for k,v in host_tunnel_rtt.items()}

# ---------------- Read Three-node RTT ----------------
three_node_rtt = []  # (node1, node3, rtt1to2to3_ms)
with open(three_node_csv, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        node1 = row["Node_A"]
        node3 = row["Node_B"]
        delay_s = float(row["Delay"])
        three_node_rtt.append((node1, node3, delay_s * 1000))  # Convert to ms

# ---------------- Construct Node Set ----------------
nodes = set()
for host, tunnel in host_tunnel_avg.keys():
    nodes.update([host, tunnel])
for node1, node3, _ in three_node_rtt:
    nodes.update([node1, node3])
nodes = sorted(nodes)

# ---------------- Populate All Pair Delays ----------------
all_delays = {}  # (node_a, node_b) -> delay

# Host <-> Tunnel
for (host, tunnel), delay in host_tunnel_avg.items():
    all_delays[(host, tunnel)] = delay
    all_delays[(tunnel, host)] = delay  # Symmetric

# Tunnel <-> Tunnel (Derived from three-node RTT)
for node1, node3, rtt_1to2to3 in three_node_rtt:
    for (host, tunnel), host_to_tunnel_rtt in host_tunnel_avg.items():
        if tunnel == node1:
            rtt1_2 = host_to_tunnel_rtt
            key_1_3 = (host, node3)
            rtt1_3 = host_tunnel_avg.get(key_1_3)
            if rtt1_3 is None:
                continue
            delay_derived = rtt_1to2to3 - rtt1_2/2 - rtt1_3/2
            all_delays[(node1, node3)] = delay_derived
            all_delays[(node3, node1)] = delay_derived

# ---------------- Output Three-column CSV ----------------
with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Node_A", "Node_B", "Delay"])
    for (a,b), delay in all_delays.items():
        writer.writerow([a,b,delay])

print(f"Output complete: {output_csv}")