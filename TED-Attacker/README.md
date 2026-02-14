# TED: Core Logic & Attack Planner

This repository contains the core logic of  **TED Attacker**, including all other aspects except tunnel node scanning: Path Delay Measurement, Packet Construction and Scheduling, Packet Injection, etc.

Unlike the scanner component (which focuses on node discovery), this module consumes network measurement data (latency, MTU) to construct multi-hop nested tunnel paths and generate precise packet transmission schedules. Its primary goal is to solve the **Inverse Timing Problem**: synchronizing asynchronously transmitted packets so they converge at the target simultaneously, thereby maximizing the pulse amplification factor.

## Key Features

* **Dynamic Path Construction**: Automatically constructs multi-hop forwarding paths (onion routing) using available tunnel nodes.
* **MTU-Aware Nesting**: Dynamically limits tunnel nesting depth based on the path's minimum MTU to prevent fragmentation or packet loss.
* **Pulse Synchronization**: Solves the send-time schedule problem to ensure packets arrive within a specific microsecond-level target window.
* **Resource Constraints**: Respects physical constraints, including sender bandwidth (`MAX_BITS`) and maximum node usage (`NODE_LIMIT`).
* **Grid Search Optimization**: Automatically searches for the optimal combination of Time Window ($C$) and Node Count ($N$) to maximize attack impact.

## The Algorithm: Dynamic Greedy Pruning

To overcome the combinatorial explosion inherent in multi-hop path selection, this project implements the **Dynamic Greedy Pruning Path Selection Algorithm**.

### Core Logic

1.  **Latency Abstraction**: Network latency is abstracted into two atomic types:
    * $T_{next}$: Latency from Current Node $\to$ Next Intermediate Node.
    * $T_{victim}$: Latency from Current Node $\to$ Last Hop $\to$ Victim.
2.  **Priority Lists (PL)**: For every node, a sorted list of neighbors is pre-calculated based on latency to speed up path extension.
3.  **Incremental Construction**: Paths are built layer by layer. The algorithm expands from 1 hop to $k$ hops, prioritizing "fast" paths first to fill the earliest arrival slots in the schedule.

### Pruning Mechanisms

* **Time Pruning**: If a path's total delay exceeds the Attack Window ($C$), the search on that branch stops immediately.
* **Bandwidth Pruning**: If a specific 1ms time slot at the sender is full (based on `MAX_BITS`), that slot is skipped to prevent self-congestion.
* **MTU Pruning**: If adding a layer causes the packet size to exceed the path's minimum MTU, the path extension stops.
## Input Data Format

The script requires four specific CSV/TXT files derived from the measurement phase. Ensure your data follows these formats.
> **Note:** Nodes with "Timeout", "-1.000" delay, or "0" MTU are automatically banned during the loading phase.

### 1. Host to Tunnel Node Latency (`host2tun`)
Records the RTT/One-way delay from the attacker to the entry tunnel node.
* **Format**: `Node_IP Delay_ms`
* **Example**:
    ```text
    2001:1284:60ff:16::1 634.222
    2001:1284:60ff:fffe::1 559.188
    2001:1284:7005:3000::1 Timeout
    ```

### 2. Tunnel Node to Tunnel Node Latency (`node2node`)
Records the latency between intermediate tunnel nodes.
* **Format**: `Node_A,Node_B,Seq,Delay_s`
* **Example**:
    ```csv
    Node_A,Node_B,Seq,Delay
    2001:1248::1,2604:a880::2,36328,0.101485
    ```

### 3. Tunnel Node to Victim Latency (`node2victim`)
Records the latency from the exit node to the target victim (measured via TTL expiry or similar methods).
* **Format**: `Exit_Node Victim_IP Delay_ms`
* **Example**:
    ```text
    2001:1278:4000:8::5 2401:c080::1 -1.000
    2001:1284:20ff:8::2 2401:c080::1 345.734
    ```

### 4. MTU Data (`mtu.csv`)
Records the Path MTU for each node to ensure nested packets fit without fragmentation.
* **Format**: `Node,MTU`
* **Example**:
    ```csv
    Node,MTU
    2404:8000:1745:1::1a2,1480
    2404:8000:1745:1::1c5,1639
    ```


## Configuration

You can adjust the attack simulation parameters in `config.py` (or at the top of the main script):

```python
# Attacker Host Constraints
MAX_BITS = 200000000  # Bandwidth limit: 200 Mbps (prevent self-congestion)
HOST_MTU = 1200       # The MTU of the attacker's network interface

# Algorithm Constraints
TIME_WINDOW = 5.0     # Attack accumulation window (C) in seconds
NODE_LIMIT = 2000     # Max number of best nodes to use (N)
```


## SAV Compliance

The path construction logic strictly adheres to Source Address Validation (SAV) principles:

* **ISAV**: Inbound traffic uses legitimate public addresses.
* **OSAV**: Outbound traffic from the attacker uses the attacker's true source address.
* **Nested**: Inner headers are encapsulated and forwarded by legitimate tunnel endpoints, appearing as valid traffic flows.

## Disclaimer

**Academic Research Only.** This code is part of a proof-of-concept study on network protocol security. It is intended to demonstrate vulnerabilities in IPv6 tunneling mechanisms to help vendors and operators improve security. Do not use this tool against unauthorized targets.

