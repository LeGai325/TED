/**
 * tunnel_sender.c
 * * Compile command: gcc -o tunnel_sender tunnel_sender.c -lpthread
 * * Run command: sudo ./tunnel_sender -f addresses.txt
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/time.h>
#include <getopt.h>
#include <stdatomic.h>

// ================= Configuration Constants =================
#define DEFAULT_SRC_ADDR "" // Placeholder: Set via -s or fill in
#define PACKET_INTERVAL_US 10000 // 0.01s = 10000us
#define FRAG_BASE 0x100000
#define MAX_NODES 210000
#define MAX_PACKET_SIZE 1500
#define SEQ_MAP_SIZE 65536 // Simple hash map size
#define RESULT_CSV "result.csv" // Default filename
#define NUM_WORKER_THREADS 10 // Number of sender threads

// ================= Data Structures =================

// Simple send record table (Seq -> Info)
typedef struct {
    int active;
    double send_time;
    char node_a[40];
    char node_b[40];
    pthread_mutex_t lock;
} SendRecord;

SendRecord record_map[SEQ_MAP_SIZE];

// Node list
char node_list[MAX_NODES][46];
int node_count = 0;

// Configuration parameters
char src_addr_str[46];
char txt_path[256];
int samples_per_pair = 1;

// Statistics
atomic_int sent_count = 0;
atomic_int failed_count = 0;

// CSV Lock
pthread_mutex_t csv_lock = PTHREAD_MUTEX_INITIALIZER;

// IPv6 Fragment Header definition (Standard headers might not have complete bitfield definitions, manual definition is safer)
struct ip6_frag_hdr {
    uint8_t   ip6f_nxt;       // Next Header
    uint8_t   ip6f_reserved;  // Reserved
    uint16_t  ip6f_offlg;     // Offset, Reserved, and Flag
    uint32_t  ip6f_ident;     // Identification
};

// ================= Utility Functions =================

double get_current_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

// Calculate checksum
uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Calculate ICMPv6 checksum (Pseudo-header required)
uint16_t icmp6_checksum(struct ip6_hdr *ip, struct icmp6_hdr *icmp, int icmp_len) {
    char buf[4096];
    int offset = 0;
    
    // Construct pseudo-header
    // Source address (16 bytes)
    memcpy(buf + offset, &ip->ip6_src, 16); offset += 16;
    // Destination address (16 bytes)
    memcpy(buf + offset, &ip->ip6_dst, 16); offset += 16;
    // ICMPv6 length (32 bits)
    uint32_t len_net = htonl(icmp_len);
    memcpy(buf + offset, &len_net, 4); offset += 4;
    // Next two lines: 3 zero bytes + NextHeader(58)
    uint8_t zero[3] = {0, 0, 0};
    memcpy(buf + offset, zero, 3); offset += 3;
    uint8_t nxt = IPPROTO_ICMPV6;
    memcpy(buf + offset, &nxt, 1); offset += 1;

    // ICMPv6 packet content
    memcpy(buf + offset, icmp, icmp_len); offset += icmp_len;

    return checksum(buf, offset);
}

// Modify the last byte of IPv6 address (bump logic)
void bump_last_ipv6_byte(const char *in_addr_str, char *out_addr_str) {
    struct in6_addr addr;
    inet_pton(AF_INET6, in_addr_str, &addr);
    
    // logic: ((val & 0xFF) + 1) % 255
    // Note: The last byte is at s6_addr[15]
    uint8_t val = addr.s6_addr[15];
    uint8_t new_last = ((val) + 1) % 255;
    
    // Keep original logic: Only replace the last byte, do not clear the second to last byte (unless overflow, but Python logic is bitwise)
    // Python: bumped = (val & (~0xFF)) | new_last
    // C handling of byte streams is more direct
    addr.s6_addr[15] = new_last;

    inet_ntop(AF_INET6, &addr, out_addr_str, 46);
}

void write_delay_result(const char *node_a, const char *node_b, int seq, double delay) {
    pthread_mutex_lock(&csv_lock);
    
    int newfile = 0;
    if (access(RESULT_CSV, F_OK) == -1) {
        newfile = 1;
    }

    FILE *fp = fopen(RESULT_CSV, "a");
    if (fp) {
        if (newfile) {
            fprintf(fp, "Node_A,Node_B,Seq,Delay\n");
        }
        fprintf(fp, "%s,%s,%d,%.6f\n", node_a, node_b, seq, delay);
        fflush(fp);
        fclose(fp);
    } else {
        perror("Failed to write CSV");
    }

    pthread_mutex_unlock(&csv_lock);
}

// ================= Send Logic =================

// Construct and send complex 3-layer encapsulated packet
int craft_and_send(int sock, const char *src, const char *node_a, const char *node_b, int icmp_id, int icmp_seq) {
    char packet[MAX_PACKET_SIZE];
    memset(packet, 0, MAX_PACKET_SIZE);

    struct sockaddr_in6 dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, node_a, &dst_addr.sin6_addr); // Physical destination is Node A

    // Prepare IP addresses
    struct in6_addr src_bin, node_a_bin, node_b_bin;
    struct in6_addr middle_src_bin, inner_src_bin;
    char middle_src_str[46], inner_src_str[46];

    inet_pton(AF_INET6, src, &src_bin);
    inet_pton(AF_INET6, node_a, &node_a_bin);
    inet_pton(AF_INET6, node_b, &node_b_bin);

    bump_last_ipv6_byte(node_a, middle_src_str);
    bump_last_ipv6_byte(node_b, inner_src_str);
    
    inet_pton(AF_INET6, middle_src_str, &middle_src_bin);
    inet_pton(AF_INET6, inner_src_str, &inner_src_bin);

    // --- 1. Construct Inner Packet (IPv6 + Frag + ICMPv6) ---
    // Calculate Payload
    char payload[64];
    int payload_len = snprintf(payload, sizeof(payload), "TUNNEL:%s->%s:%d", node_a, node_b, icmp_seq);
    
    // ICMPv6 Header
    struct icmp6_hdr icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    icmp_hdr.icmp6_code = 0;
    icmp_hdr.icmp6_id = htons(icmp_id);
    icmp_hdr.icmp6_seq = htons(icmp_seq);
    // Calculate checksum later

    // Inner Fragment Header
    struct ip6_frag_hdr inner_frag;
    inner_frag.ip6f_nxt = IPPROTO_ICMPV6; 
    inner_frag.ip6f_reserved = 0;
    inner_frag.ip6f_offlg = 0; // Offset=0, M=0
    inner_frag.ip6f_ident = htonl(FRAG_BASE + icmp_seq);

    // Inner IPv6 Header (Pseudo-header need for ICMP checksum)
    struct ip6_hdr inner_ip;
    inner_ip.ip6_flow = htonl(0x60000000); // Version 6
    inner_ip.ip6_plen = htons(sizeof(inner_frag) + sizeof(icmp_hdr) + payload_len);
    inner_ip.ip6_nxt = 44; // IPPROTO_FRAGMENT
    inner_ip.ip6_hlim = 64;
    inner_ip.ip6_src = inner_src_bin;
    inner_ip.ip6_dst = src_bin; // Inner dst is SRC

    // Calculate ICMP Checksum (Requires Inner IP context)
    // Temporarily construct ICMP body to calculate checksum
    char icmp_full[128];
    memcpy(icmp_full, &icmp_hdr, sizeof(icmp_hdr));
    memcpy(icmp_full + sizeof(icmp_hdr), payload, payload_len);
    icmp_hdr.icmp6_cksum = icmp6_checksum(&inner_ip, (struct icmp6_hdr*)icmp_full, sizeof(icmp_hdr) + payload_len);

    // Assemble Inner Packet data block (No IPv6 header, just payload part, because we are nesting)
    // Structure: [FragHdr][ICMP][Payload]
    // Note: When nesting, the payload of the upper layer is the complete IP packet (or fragment) of the lower layer
    
    // Actually Scapy nesting is: OuterIPv6 / MiddleIPv6 / Frag / InnerIPv6 / Frag / ICMP
    // Rechecking Python code:
    // inner = IPv6(src=inner_src, dst=src) / IPv6ExtHdrFragment(...) / inner_icmp
    // middle = IPv6(src=middle_src, dst=node_b) / IPv6ExtHdrFragment(...) / inner
    // outer = IPv6(src=src, dst=node_a) / middle

    // Re-plan buffer pointers
    uint8_t *ptr = (uint8_t *)packet;
    
    // --- L1: Outer IPv6 ---
    struct ip6_hdr *l1_ip = (struct ip6_hdr *)ptr;
    ptr += sizeof(struct ip6_hdr);

    // --- L2: Middle IPv6 ---
    struct ip6_hdr *l2_ip = (struct ip6_hdr *)ptr;
    ptr += sizeof(struct ip6_hdr);

    // --- L2: Middle Frag ---
    struct ip6_frag_hdr *l2_frag = (struct ip6_frag_hdr *)ptr;
    ptr += sizeof(struct ip6_frag_hdr);

    // --- L3: Inner IPv6 ---
    struct ip6_hdr *l3_ip = (struct ip6_hdr *)ptr;
    ptr += sizeof(struct ip6_hdr);

    // --- L3: Inner Frag ---
    struct ip6_frag_hdr *l3_frag = (struct ip6_frag_hdr *)ptr;
    ptr += sizeof(struct ip6_frag_hdr);

    // --- L3: ICMPv6 ---
    struct icmp6_hdr *l3_icmp = (struct icmp6_hdr *)ptr;
    ptr += sizeof(struct icmp6_hdr);

    // --- Payload ---
    memcpy(ptr, payload, payload_len);
    ptr += payload_len;

    int total_len = ptr - (uint8_t *)packet;

    // --- Fill layer data ---

    // 3. Inner Layer (L3)
    l3_icmp->icmp6_type = ICMP6_ECHO_REQUEST;
    l3_icmp->icmp6_code = 0;
    l3_icmp->icmp6_id = htons(icmp_id);
    l3_icmp->icmp6_seq = htons(icmp_seq);
    
    l3_frag->ip6f_nxt = IPPROTO_ICMPV6;
    l3_frag->ip6f_reserved = 0;
    l3_frag->ip6f_offlg = 0;
    l3_frag->ip6f_ident = htonl(FRAG_BASE + icmp_seq);

    l3_ip->ip6_flow = htonl(0x60000000);
    l3_ip->ip6_plen = htons(sizeof(struct ip6_frag_hdr) + sizeof(struct icmp6_hdr) + payload_len);
    l3_ip->ip6_nxt = 44; // Fragment
    l3_ip->ip6_hlim = 64;
    l3_ip->ip6_src = inner_src_bin;
    l3_ip->ip6_dst = src_bin;

    // Calculate ICMP Checksum (Must be done after all fields are filled)
    // Note: Checksum calculation needs to include Payload
    // Buffer pointer arithmetic here is tricky, constructing temporary icmp body
    char icmp_calc_buf[256];
    memcpy(icmp_calc_buf, l3_icmp, sizeof(struct icmp6_hdr));
    memcpy(icmp_calc_buf + sizeof(struct icmp6_hdr), payload, payload_len);
    l3_icmp->icmp6_cksum = icmp6_checksum(l3_ip, (struct icmp6_hdr *)icmp_calc_buf, sizeof(struct icmp6_hdr) + payload_len);


    // 2. Middle Layer (L2)
    l2_frag->ip6f_nxt = 41; // IPv6 (contains Inner IPv6)
    l2_frag->ip6f_reserved = 0;
    l2_frag->ip6f_offlg = 0;
    l2_frag->ip6f_ident = htonl(FRAG_BASE + 0x10000 + icmp_seq);

    l2_ip->ip6_flow = htonl(0x60000000);
    // Payload length = FragHdr + InnerIPv6 + InnerFrag + InnerICMP + Data
    l2_ip->ip6_plen = htons(sizeof(struct ip6_frag_hdr) + sizeof(struct ip6_hdr) + sizeof(struct ip6_frag_hdr) + sizeof(struct icmp6_hdr) + payload_len);
    l2_ip->ip6_nxt = 44; // Fragment
    l2_ip->ip6_hlim = 64;
    l2_ip->ip6_src = middle_src_bin;
    l2_ip->ip6_dst = src_bin;

    // 1. Outer Layer (L1)
    l1_ip->ip6_flow = htonl(0x60000000);
    // Payload length = MiddleIPv6 + ...
    l1_ip->ip6_plen = htons(total_len - sizeof(struct ip6_hdr)); // Total - L1 Header
    l1_ip->ip6_nxt = 41; // IPv6 (Middle)
    l1_ip->ip6_hlim = 64;
    l1_ip->ip6_src = src_bin;
    l1_ip->ip6_dst = node_a_bin;

    // Send
    ssize_t sent = sendto(sock, packet, total_len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if (sent < 0) {
        // fprintf(stderr, "Send failed: %s\n", strerror(errno));
        return 0;
    }

    // Record send time
    double now = get_current_time();
    int idx = icmp_seq % SEQ_MAP_SIZE;
    
    pthread_mutex_lock(&record_map[idx].lock);
    record_map[idx].active = 1;
    record_map[idx].send_time = now;
    strncpy(record_map[idx].node_a, node_a, 39);
    strncpy(record_map[idx].node_b, node_b, 39);
    pthread_mutex_unlock(&record_map[idx].lock);

    return 1;
}

// Task structure
typedef struct {
    int start_idx;
    int end_idx;
    int sock_fd;
} ThreadArg;

void *sender_worker(void *arg) {
    ThreadArg *t_arg = (ThreadArg *)arg;
    int local_seq = 20000 + t_arg->start_idx * 10; // Stagger sequence numbers
    
    // Generate all pairs
    // For simplicity, each thread iterates the whole list but only processes its own part
    // Better approach is to pre-generate pair list, but it consumes memory
    
    int pair_idx = 0;
    for (int i = 0; i < node_count; i++) {
        for (int j = i + 1; j < node_count; j++) {
            // Simple task distribution: Modulo
            if (pair_idx % NUM_WORKER_THREADS == t_arg->start_idx) {
                const char *node_a = node_list[i];
                const char *node_b = node_list[j];

                for (int s = 0; s < samples_per_pair; s++) {
                    int seq = local_seq++;
                    int id = 0x7000 + (seq & 0xFF);
                    
                    if (craft_and_send(t_arg->sock_fd, src_addr_str, node_a, node_b, id, seq)) {
                        atomic_fetch_add(&sent_count, 1);
                    } else {
                        atomic_fetch_add(&failed_count, 1);
                    }
                    
                    if (s < samples_per_pair - 1) usleep(PACKET_INTERVAL_US);
                }
            }
            pair_idx++;
        }
    }
    return NULL;
}

// ================= Packet Capture Thread =================

void *sniff_thread(void *arg) {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0) {
        perror("Sniffer socket error");
        exit(1);
    }

    printf("=== Sniffer started (Socket %d) ===\n", sock);

    char buffer[2048];
    while (1) {
        struct sockaddr_in6 src_addr;
        socklen_t addr_len = sizeof(src_addr);
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);

        if (len <= 0) continue;

        // Parse Packet
        // ICMPv6 packets received by raw sockets usually contain IPv6 header?
        // In Linux SOCK_RAW(IPPROTO_ICMPV6), typically only Payload (ICMPv6 Header + Data) is received
        // Or it might contain the IP header depending on system config (IPV6_RECVPKTINFO).
        // By default, Linux raw socket might strip the IPv6 header.
        // But for generality, assume it might contain IP header, need to check.
        // ICMPv6 header is at least 4 bytes (Type, Code, Cksum) + 4 bytes (ID, Seq)
        
        // Simple heuristic: Check if buffer starts with IPv6 (0x6...)
        uint8_t *ptr = (uint8_t *)buffer;
        int parsed_seq = -1;
        
        // Try to parse Sequence Number
        // 1. Try to parse "TUNNEL:..." from Payload text
        // Even if there is an IP header, Payload is at the end, strstr scanning works
        char *payload_tag = "TUNNEL:";
        // Ensure null terminator at end of buffer for strstr (though it overwrites data, we only read)
        if (len < 2048) buffer[len] = 0;
        
        char *found = strstr((char *)buffer, payload_tag);
        if (found) {
            // Format: TUNNEL:a->b:seq
            char *p = strrchr(found, ':');
            if (p) {
                parsed_seq = atoi(p + 1);
            }
        }

        // 2. If Payload parsing fails, try parsing by ICMP Offset
        if (parsed_seq == -1) {
            // Assume no IPv6 header, directly ICMPv6
            if (len >= 8) {
                struct icmp6_hdr *icmp = (struct icmp6_hdr *)buffer;
                if (icmp->icmp6_type == ICMP6_ECHO_REQUEST || icmp->icmp6_type == ICMP6_ECHO_REPLY) {
                    // Python code sends Request, receives Request (Inner Packet loopback)
                    parsed_seq = ntohs(icmp->icmp6_seq);
                }
            }
            // If there is an IPv6 header (40 bytes), offset and try again
            if (len >= 48) {
                 struct icmp6_hdr *icmp = (struct icmp6_hdr *)(buffer + 40);
                 if (icmp->icmp6_type == ICMP6_ECHO_REQUEST) {
                     parsed_seq = ntohs(icmp->icmp6_seq);
                 }
            }
        }

        if (parsed_seq != -1) {
            double recv_time = get_current_time();
            int idx = parsed_seq % SEQ_MAP_SIZE;

            pthread_mutex_lock(&record_map[idx].lock);
            if (record_map[idx].active) {
                double delay = recv_time - record_map[idx].send_time;
                // Simple Seq validation (Prevent hash collision reading old data, though probability is low)
                // Assume seq increases and doesn't wrap around quickly
                
                write_delay_result(record_map[idx].node_a, record_map[idx].node_b, parsed_seq, delay);
                printf("[MATCH] %s -> %s seq=%d, delay=%.6fs\n", 
                       record_map[idx].node_a, record_map[idx].node_b, parsed_seq, delay);
                
                // Mark as processed (Optional, or keep for retransmission detection)
                record_map[idx].active = 0; 
            }
            pthread_mutex_unlock(&record_map[idx].lock);
        }
    }
    return NULL;
}

// ================= Main Program =================

void read_nodes(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", path);
        exit(1);
    }
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        // Trim newline
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) > 2) {
            strncpy(node_list[node_count++], line, 45);
            if (node_count >= MAX_NODES) break;
        }
    }
    fclose(f);
    printf("Read %d nodes\n", node_count);
}

int main(int argc, char *argv[]) {
    // Initialize locks
    for (int i = 0; i < SEQ_MAP_SIZE; i++) {
        pthread_mutex_init(&record_map[i].lock, NULL);
        record_map[i].active = 0;
    }

    // Argument parsing
    strncpy(src_addr_str, DEFAULT_SRC_ADDR, 45);
    int opt;
    while ((opt = getopt(argc, argv, "f:s:c:")) != -1) {
        switch (opt) {
        case 'f':
            strncpy(txt_path, optarg, 255);
            break;
        case 's': // --src
            strncpy(src_addr_str, optarg, 45);
            break;
        case 'c': // count / samples
            samples_per_pair = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s -f addr.txt [-s src_addr] [-c samples]\n", argv[0]);
            exit(1);
        }
    }

    if (strlen(txt_path) == 0) {
        fprintf(stderr, "Please specify address file using -f\n");
        exit(1);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: Root privileges required (Raw Sockets)\n");
        exit(1);
    }

    read_nodes(txt_path);

    // Start Sniffer thread
    pthread_t sniffer;
    pthread_create(&sniffer, NULL, sniff_thread, NULL);

    // Create send Socket (Each thread can use the same one, or separate ones, here separate is safer)
    // To simplify, we create in main or inside worker.
    // Is raw socket thread safe? Generally sendto is atomic.
    // We let each worker create its own socket.
    
    pthread_t workers[NUM_WORKER_THREADS];
    ThreadArg args[NUM_WORKER_THREADS];

    printf("Starting send tasks (Concurrent threads: %d)...\n", NUM_WORKER_THREADS);

    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        args[i].start_idx = i;
        args[i].sock_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW); // IPPROTO_RAW allows us to construct full packet
        if (args[i].sock_fd < 0) {
            perror("Socket creation failed");
            // Some systems don't support IPPROTO_RAW for IPv6, try IPPROTO_RAW
            // Linux IPv6 Raw socket sending usually uses IPPROTO_RAW
        }
        pthread_create(&workers[i], NULL, sender_worker, &args[i]);
    }

    // Wait for sending to complete
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        pthread_join(workers[i], NULL);
        close(args[i].sock_fd);
    }
    
    int final_success = atomic_load(&sent_count);
    int final_failed = atomic_load(&failed_count);
    int total_attempts = final_success + final_failed;

    printf("\n");
    printf("########################################\n");
    printf("#        Send Task Statistics Report       #\n");
    printf("########################################\n");
    printf("# Total Attempts : %d packets\n", total_attempts);
    printf("# Send Success   : %d\n", final_success);
    printf("# Send Failed    : %d\n", final_failed);
    
    if (total_attempts > 0) {
        float success_rate = (float)final_success / total_attempts * 100.0f;
        printf("# Success Rate   : %.2f%%\n", success_rate);
    }
    printf("########################################\n");
    printf("\n");

    printf("Sending complete: Success %d, Failed %d\n", sent_count, failed_count);
    printf("Waiting 20 seconds to receive remaining packets...\n");
    sleep(20);

    // Actually Sniffer is an infinite loop, just exit directly
    return 0;
}