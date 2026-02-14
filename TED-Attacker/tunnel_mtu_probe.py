'''
Tunnel Node MTU Testing
'''
import csv
import threading
import queue
import time
from scapy.all import *

# Configuration
INPUT_CSV = "delay_results.csv"  # Placeholder: Set this to your actual file path
OUTPUT_CSV = "mtu_results.csv"
MIN_MTU = 1280
MAX_MTU = 2000
TIMEOUT = 2
IFACE = ""  # Sending interface
THREAD_NUM = 16

# Thread queue
node_queue = queue.Queue()
results = []
results_lock = threading.Lock()

def read_nodes(csv_file):
    """Read CSV file and extract unique node addresses"""
    nodes = set()
    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            nodes.add(row['Node_A'])
            nodes.add(row['Node_B'])
    return list(nodes)

def mtu_probe(node):
    """Perform binary search MTU probing for a single node"""
    low, high = MIN_MTU, MAX_MTU
    best_mtu = 0

    while low <= high:
        mid = (low + high) // 2
        payload_len = mid - 48  # IPv6(40)+ICMPv6(8)
        if payload_len <= 0:
            break
        pkt = IPv6(dst=node)/ICMPv6EchoRequest(data="X"*payload_len)
        try:
            # Non-blocking send + sniff capture
            ans = sr1(pkt, timeout=TIMEOUT, verbose=0)
            if ans is None:
                # Timeout or unreachable
                high = mid - 1
            elif ans.haslayer(ICMPv6PacketTooBig):
                high = mid - 1
            else:
                best_mtu = mid
                low = mid + 1
        except Exception:
            high = mid - 1

    with results_lock:
        results.append((node, best_mtu))
    print(f"[{threading.current_thread().name}] {node} Max reachable MTU: {best_mtu}")

def worker():
    while True:
        try:
            node = node_queue.get_nowait()
        except queue.Empty:
            break
        mtu_probe(node)
        node_queue.task_done()

def main():
    nodes = read_nodes(INPUT_CSV)
    print(f"Found {len(nodes)} unique nodes, starting MTU probing...")

    # Enqueue
    for node in nodes:
        node_queue.put(node)

    threads = []
    for i in range(min(THREAD_NUM, len(nodes))):
        t = threading.Thread(target=worker, name=f"Thread-{i+1}")
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Write to CSV
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Node', 'MTU'])
        writer.writerows(results)

    print(f"Probing complete, results saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()