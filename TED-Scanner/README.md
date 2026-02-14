
# TED: Abusing Tunnel Hosts and IPv6 Extension Headers for Pulsing DoS Attacks

**TED** (TED: Abusing Tunnel Hosts and IPv6 Extension Headers for Pulsing DoS Attacks) is a specialized network scanning and analysis framework designed to investigate vulnerabilities in IPv6 tunneling mechanisms. Built upon the architecture of ZMap, TED extends standard scanning capabilities to identify and evaluate tunnel nodes (IPIP, GRE, 6in4, IP6IP6, etc.) that are susceptible to packet manipulation via IPv6 Extension Headers.

This tool was developed to support the research paper *"TED: Abusing Tunnels and IPv6 Extension Headers for Pulsing DoS Attacks."* It enables researchers to identify vulnerable tunnel endpoints that can be weaponized to forward nested packets or generate high-amplification pulsing traffic.

## Disclaimer

**Research Purposes Only:** This code is provided solely for educational and academic research purposes. The authors do not endorse or encourage the use of this tool for malicious activities. Users are responsible for ensuring that their scanning activities comply with all applicable local, state, and federal laws.

## Installation

Instructions on building TED from the source can be found in the `INSTALL` file. As this project extends ZMap, dependencies are similar to the core ZMap project (CMake, GMP, Gengetopt, etc.).

## Usage

General usage follows the standard ZMap syntax. Detailed guides can be found in GitHub [Wiki](https://github.com/zmap/zmap/wiki).

### Additional Arguments

Most tunneling probe modules included in TED accept specific arguments to handle routing, spoofing, and identification. The key arguments are:

* `--external-ipv4-address $IPV4_ADDR`:
    Refers to the global IPv4 address of the scanning host. This argument ensures responses are correctly routed back to the scanner.

* `--external-ipv6-address $IPV6_ADDR`:
    Refers to the global IPv6 address of the scanning host. This argument ensures responses are correctly routed back to the scanner.

* `--spoofing-address-v4 $RANDOM_IPV4`:
    A chosen spoofed IPv4 address. This argument allows for the identification of unfiltered networks (i.e., vulnerable hosts will send a response with the given spoofed IPv4 address as the source address).

* `--spoofing-address-v6 $RANDOM_IPV6`:
    A chosen spoofed IPv6 address. This argument allows for the identification of unfiltered networks (i.e., vulnerable hosts will send a response with the given spoofed IPv6 address as the source address).

* `-f, --output-fields`:
    Some modules require specific output fields to ensure the correct address of the vulnerable host is captured (distinguishing the tunnel endpoint from the potentially spoofed source address of the reply).

## Tunneling Protocol Modules

TED introduces support for identifying vulnerable tunneling protocols through specific probe modules.

### 1. IPIP (IPv4-in-IPv4)
**Module:** `ipip_echo`
Performs an ICMP Echo/Reply scan where the ping reply typically has a source IP address equal to the host being scanned.

```bash
zmap -M ipip_echo --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR
```

### 2. GRE (Generic Routing Encapsulation)

**Module:** `gre`

Standard GRE scan to identify endpoints accepting GRE-encapsulated packets.

```bash
zmap -M gre --output-module="csv" -o output.csv --external-ipv4-address $IPV4_ADDR
```

### 3. 6in4 (IPv6-in-IPv4)

**Module:** `6to4_scan`

Detects 6to4 relays. The inner IPv6 packet has the target's 6to4 address as the source and the `external-ipv6-address` as the destination.

*Note: The output will contain the vulnerable IPv4 host's mapped address (e.g., `2002:VULN_IPv4_ADDR` or `::ffff:VULN_IPv4_ADDR`).*

```bash
zmap -M 6to4_scan --external-ipv6-address $IPV6_ADDR -o output.csv -f saddr
```

### 4. GRE6 (IPv6 GRE)

**Module:** `gre6_icmp`

Performs an ICMPv6 Echo/Reply scan over GRE6. The ping reply source IP indicates the scanned host.

```Bash
zmap -M gre6_icmp --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt -o output.csv
```

### 5. IP6IP6 (IPv6-in-IPv6)

**Module:** `ip6ip6_echo`

Implements the methodology described in **Section 3.2.2** of the paper. It performs an ICMPv6 Echo/Reply scan to identify nested tunnel capabilities.

```Bash
zmap -M ip6ip6_echo --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addresses.txt --spoofing-address-v6 $RANDOM_ADDR_V6 -o output.csv
```

### 6. 4in6 (IPv4-in-IPv6)

**Module:** `4in6_ttl`

Performs a TTL Expired scan. The inner source address is set to `external-ipv4-address` and the destination to `spoofing-address-v4`, with the inner packet TTL set to 1.

*Note: `actual_src_index` corresponds to the index line of the `ipv6_addr.txt` for the host.*

```Bash
zmap -M 4in6_ttl --ipv6-source-ip $IPV6_ADDR --ipv6-target-file ipv6_addr.txt --spoofing-address-v4 $RANDOM_ADDR --external-ipv4-address $IPV4_ADDR -o output.csv -f actual_src_index,tunnel_addr
```

## License and Copyright

**TED Copyright 2026**

(Based on ZMap Copyright 2017 Regents of the University of Michigan)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
