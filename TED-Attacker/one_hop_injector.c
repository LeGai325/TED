#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>

#define LOCAL_ADDR  "2001:db8::1" // Placeholder: Replace with actual local address
#define TARGET_ADDR "2001:db8::2" // Placeholder: Replace with actual target address

#define MAX_PATH_NODES 32
#define MAX_PACKET_SIZE 1500
#define MAX_RECORDS 500000

/* ================= Structure Definitions ================= */

/* Pseudo-header required for IPv6 checksum calculation */
struct ip6_pseudo_hdr {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t ulpl;      /* Upper Layer Packet Length */
    uint8_t  zero[3];
    uint8_t  next_hdr;
} __attribute__((packed));

typedef struct {
    char     path_raw[1024];
    char     nodes[MAX_PATH_NODES][INET6_ADDRSTRLEN];
    int      n_nodes;
    double   scheduled_send_time; // send_time_s read from CSV
    double   abs_send_time;       // Calculated absolute send time (Monotonic Time)
    uint32_t seq_id;              // Sequence ID to identify the packet
} record_t;

/* ================= Global Variables ================= */

static record_t records[MAX_RECORDS]; 

static int crafted_packets = 0;
static int sent_packets    = 0;

/* ================= Time Utilities ================= */

// Get current time from monotonic clock (seconds)
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// Busy wait/sleep until specified time
static void sleep_until(double abs_time) {
    while (1) {
        double cur = now_sec();
        if (cur >= abs_time)
            break;
        
        double remain = abs_time - cur;
        
        // If remaining time > 1ms, use nanosleep to yield CPU
        // If < 1ms, use busy wait for precision
        if (remain > 0.001) {
            struct timespec ts;
            ts.tv_sec  = (time_t)remain;
            ts.tv_nsec = (remain - ts.tv_sec) * 1e9;
            nanosleep(&ts, NULL);
        } else {
            // Busy wait (Spin lock)
            // Empty loop
        }
    }
}

/* ================= Checksum Calculation ================= */

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
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

static uint16_t calculate_icmpv6_checksum(struct ip6_hdr *ip, struct icmp6_hdr *icmp, int icmp_len) {
    char buf[40 + icmp_len]; 
    struct ip6_pseudo_hdr ph;

    memset(&ph, 0, sizeof(ph));
    ph.src = ip->ip6_src;
    ph.dst = ip->ip6_dst;
    ph.ulpl = htonl(icmp_len);
    ph.next_hdr = IPPROTO_ICMPV6;

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), icmp, icmp_len);

    return checksum(buf, sizeof(ph) + icmp_len);
}

/* ================= Path Parsing ================= */

static int parse_path(char *path,
                      char nodes[MAX_PATH_NODES][INET6_ADDRSTRLEN]) {
    int count = 0;
    
    // Copy path because strtok modifies the original string
    char path_copy[1024];
    strncpy(path_copy, path, sizeof(path_copy)-1);
    path_copy[sizeof(path_copy)-1] = '\0';

    // Handle path delimiters from Python output (assumed space, "->", or others)
    // Based on previous Python code: path_str.replace('->', ' ').split()
    // Here path_raw is cleaned, likely space-separated already
    
    char *token = strtok(path_copy, " ->"); // Supports both space and arrow
    while (token && count < MAX_PATH_NODES) {
        // Remove potential whitespace
        while (*token == ' ') token++;
        
        if (strlen(token) > 0) {
            strncpy(nodes[count], token, INET6_ADDRSTRLEN - 1);
            nodes[count][INET6_ADDRSTRLEN - 1] = '\0';
            count++;
        }
        token = strtok(NULL, " ->");
    }
    return count;
}

/* ================= Packet Construction ================= */

/**
 * Construct IP6-in-IP6 Packet (No Extension Header)
 * Structure: [Outer IPv6 (NH=41)] -> [Inner IPv6 (NH=58)] -> [ICMPv6 Echo]
 * * Note: Payload now writes the [Actual Expected Physical Send Time] for tcpdump comparison
 */
static int build_packet(uint8_t *buf,
                        char nodes[][INET6_ADDRSTRLEN],
                        int n_nodes,
                        uint32_t seq_id,
                        const char *path_str,
                        double abs_send_time) 
{
    if (n_nodes < 1) return -1;

    // Tunnel node address (first node in path)
    const char *tunnel_node_addr = nodes[0];
    
    uint8_t *p = buf;

    /* ---------- 1. Prepare Payload (Data Section) ---------- */
    char payload_data[512]; 
    
    // Get current real time for record (not monotonic), for debugging
    struct timespec ts_real;
    clock_gettime(CLOCK_REALTIME, &ts_real);
    double real_ts = ts_real.tv_sec + ts_real.tv_nsec / 1e9;

    int payload_len = snprintf(payload_data, sizeof(payload_data), 
                               "SEQ:%u|TS:%.6f|PATH:%s", 
                               seq_id, real_ts, path_str);

    if (payload_len >= sizeof(payload_data)) {
        payload_len = sizeof(payload_data) - 1;
    }

    /* ---------- 2. Prepare Inner IPv6 Header ---------- */
    struct ip6_hdr inner_ip;
    memset(&inner_ip, 0, sizeof(inner_ip));
    
    inet_pton(AF_INET6, TARGET_ADDR, &inner_ip.ip6_dst);
    inet_pton(AF_INET6, tunnel_node_addr, &inner_ip.ip6_src);
    // Fake source address: +1
    inner_ip.ip6_src.s6_addr[15] = (inner_ip.ip6_src.s6_addr[15] + 1) % 255;

    inner_ip.ip6_vfc  = 6 << 4;
    inner_ip.ip6_nxt  = IPPROTO_ICMPV6; 
    inner_ip.ip6_hlim = 64;
    
    int icmp_total_len = sizeof(struct icmp6_hdr) + payload_len;
    inner_ip.ip6_plen = htons(icmp_total_len);

    /* ---------- 3. Prepare ICMPv6 ---------- */
    uint8_t icmp_full_packet[sizeof(struct icmp6_hdr) + 512]; 
    struct icmp6_hdr *icmp_hdr = (struct icmp6_hdr *)icmp_full_packet;

    memset(icmp_hdr, 0, sizeof(struct icmp6_hdr));
    icmp_hdr->icmp6_type  = ICMP6_ECHO_REQUEST;
    icmp_hdr->icmp6_code  = 0;
    icmp_hdr->icmp6_id    = htons(0x4242);
    icmp_hdr->icmp6_seq   = htons(seq_id & 0xffff);
    icmp_hdr->icmp6_cksum = 0; 

    memcpy(icmp_full_packet + sizeof(struct icmp6_hdr), payload_data, payload_len);
    icmp_hdr->icmp6_cksum = calculate_icmpv6_checksum(&inner_ip, icmp_hdr, icmp_total_len);

    /* ---------- 4. Prepare Outer IPv6 Header ---------- */
    struct ip6_hdr outer_ip;
    memset(&outer_ip, 0, sizeof(outer_ip));

    inet_pton(AF_INET6, tunnel_node_addr, &outer_ip.ip6_dst);
    inet_pton(AF_INET6, LOCAL_ADDR, &outer_ip.ip6_src);

    outer_ip.ip6_vfc  = 6 << 4;
    outer_ip.ip6_nxt  = IPPROTO_IPV6; // NH=41
    outer_ip.ip6_hlim = 64;
    
    int inner_packet_len = sizeof(struct ip6_hdr) + icmp_total_len;
    outer_ip.ip6_plen = htons(inner_packet_len);

    /* ---------- 5. Assemble ---------- */
    memcpy(p, &outer_ip, sizeof(outer_ip));
    p += sizeof(outer_ip);

    memcpy(p, &inner_ip, sizeof(inner_ip));
    p += sizeof(inner_ip);

    memcpy(p, icmp_full_packet, icmp_total_len);
    p += icmp_total_len;

    return (p - buf); 
}

/* ================= CSV Reading and Scheduling ================= */

// [Core Modification] Sort by scheduled_send_time ascending
static int cmp_send_time_asc(const void *a, const void *b) {
    const record_t *ra = a;
    const record_t *rb = b;
    if (ra->scheduled_send_time < rb->scheduled_send_time) return -1;
    if (ra->scheduled_send_time > rb->scheduled_send_time) return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <schedule_csv_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    int rec_cnt = 0;
    char line[4096];

    // Skip CSV header
    if (!fgets(line, sizeof(line), fp)) { 
        fprintf(stderr, "Empty file\n");
        return 1;
    }

    printf("[*] Loading schedule from %s ...\n", argv[1]);

    // Read CSV: path, total_delay_s, send_time_s, send_slot_ms
    while (fgets(line, sizeof(line), fp) && rec_cnt < MAX_RECORDS) {
        // CSV format parsing (Assuming fields not quoted, simple handling)
        char *path_str    = strtok(line, ",");
        char *delay_str   = strtok(NULL, ",");
        char *send_ts_str = strtok(NULL, ",");
        // send_slot_ms ignored

        if (!path_str || !send_ts_str) continue;

        record_t *r = &records[rec_cnt];
        
        snprintf(r->path_raw, sizeof(r->path_raw), "%s", path_str);
        
        // [Critical] Directly read send time calculated by Python
        r->scheduled_send_time = atof(send_ts_str);
        r->seq_id = rec_cnt + 1; // Generate unique sequence ID

        // Parse nodes
        r->n_nodes = parse_path(r->path_raw, r->nodes);
        if (r->n_nodes <= 0) continue;

        rec_cnt++;
    }
    fclose(fp);
    printf("[*] Loaded %d records.\n", rec_cnt);

    // [Critical] Must sort by send time to ensure sleep_until works correctly
    qsort(records, rec_cnt, sizeof(record_t), cmp_send_time_asc);
    printf("[*] Records sorted by send_time.\n");

    // Create RAW socket
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    int sndbuf = 4 * 1024 * 1024; // Increase send buffer
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* ================= Send Loop ================= */
    
    printf("[*] Starting transmission in 1 second...\n");
    sleep(1);

    // Set base time: Current time is T=0
    double base_time = now_sec();
    
    // If Python output send_time_s does not start from 0 (e.g., absolute timestamp),
    // offset is needed here. But in your Python code, send_time_s is relative time starting from 0.0.
    // So: Actual Send Time = base_time + scheduled_send_time

    for (int i = 0; i < rec_cnt; i++) {
        record_t *r = &records[i];

        // Calculate absolute send time
        r->abs_send_time = base_time + r->scheduled_send_time;

        uint8_t packet[MAX_PACKET_SIZE];
        
        // Construct packet
        int pkt_len = build_packet(packet,
                                   r->nodes,
                                   r->n_nodes,
                                   r->seq_id,
                                   r->path_raw,
                                   r->abs_send_time);
        
        if (pkt_len < 0) continue; 

        // [Core] Wait precisely until send time
        sleep_until(r->abs_send_time);

        // Send
        struct sockaddr_in6 dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin6_family = AF_INET6;
        inet_pton(AF_INET6, r->nodes[0], &dst.sin6_addr);

        if (sendto(sock, packet, pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst)) > 0) {
            sent_packets++;
        } else {
            // Send failure should not interrupt, just record error
            // perror("sendto"); 
        }
    }

    close(sock);
    
    double end_time = now_sec();
    printf("\n=== Transmission Complete ===\n");
    printf("Total Duration   : %.4f s\n", end_time - base_time);
    printf("Packets Scheduled: %d\n", rec_cnt);
    printf("Packets Sent     : %d\n", sent_packets);

    return 0;
}