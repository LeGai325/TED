// tunnel_victim_tracer.c
// Compile: gcc -o step5 tunnel_victim_tracer.c -lpthread
// Usage: sudo ./step5 <Local IPv6> <Targets File> <Receiver IPv6> <Output File>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>

// ================= Configuration Area =================
#define BUFFER_SIZE 4096
#define MAX_TARGETS 200000    // Max supported tunnel nodes
#define MAX_HOPS 30           // Traceroute max hops
#define PACKETS_PER_HOP 1     // Packets per hop (Suggest 1 or 2 for speed)
#define TIMEOUT_SEC 10        // Extra wait seconds for receiver after sending finishes
// Max Records = Targets * Hops * Packets/Hop
#define MAX_PACKET_RECORDS (MAX_TARGETS * MAX_HOPS * PACKETS_PER_HOP) 
// ===========================================

// Tunnel Target Structure
typedef struct {
    struct in6_addr tunnel_addr;     // Tunnel Node Address (Outer Dst)
    char tunnel_addr_str[INET6_ADDRSTRLEN];
    
    double final_rtt;                // RTT to Receiver (-1 if not reached)
    int reached_dest;                // Flag: Reply received from Receiver
    int best_ttl;                    // TTL value when destination reached
} target_info_t;

// Packet Record Structure (For matching replies)
typedef struct {
    uint16_t id;
    uint16_t seq;
    int target_index;                // Index in targets array
    int ttl;                         // Sent TTL
    struct timespec send_time;
    int matched;                     // Flag: Reply matched
} packet_record_t;

// Global Variables
target_info_t targets[MAX_TARGETS];
packet_record_t packet_records[MAX_PACKET_RECORDS];
int target_count = 0;
int packet_count = 0;

struct in6_addr local_addr;      // Local Address (Inner Src)
struct in6_addr final_dest_addr; // Receiver Host Address (Inner Dst)

int send_sockfd = -1;
int recv_sockfd = -1;

// === Global State Flags ===
volatile int send_done = 0; 
time_t send_finish_time = 0;
// ===============================

// Mutexes
pthread_mutex_t record_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t target_mutex = PTHREAD_MUTEX_INITIALIZER;

// ================= Hash Table (Fast ID+Seq Lookup) =================
#define HASH_TABLE_SIZE 65536
typedef struct hash_entry {
    uint32_t key;
    int record_index;
    struct hash_entry *next;
} hash_entry_t;

hash_entry_t *hash_table[HASH_TABLE_SIZE] = {NULL};

uint32_t hash_key(uint16_t id, uint16_t seq) {
    return (id << 16) | seq;
}

void add_to_hash_table(uint16_t id, uint16_t seq, int record_index) {
    uint32_t key = hash_key(id, seq);
    int slot = key % HASH_TABLE_SIZE;
    
    hash_entry_t *entry = malloc(sizeof(hash_entry_t));
    entry->key = key;
    entry->record_index = record_index;
    entry->next = hash_table[slot];
    hash_table[slot] = entry;
}

int find_in_hash_table(uint16_t id, uint16_t seq) {
    uint32_t key = hash_key(id, seq);
    int slot = key % HASH_TABLE_SIZE;
    
    hash_entry_t *entry = hash_table[slot];
    while (entry) {
        if (entry->key == key) {
            return entry->record_index;
        }
        entry = entry->next;
    }
    return -1;
}

void cleanup_hash_table() {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        hash_entry_t *entry = hash_table[i];
        while (entry) {
            hash_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        hash_table[i] = NULL;
    }
}

// ================= Utility Functions =================

int parse_ipv6_addr(const char *addr_str, struct in6_addr *addr) {
    return inet_pton(AF_INET6, addr_str, addr);
}

void get_current_time(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

double time_diff_ms(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 + 
           (end->tv_nsec - start->tv_nsec) / 1000000.0;
}

// Checksum Calculation
uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

uint16_t icmp6_checksum(struct in6_addr *src, struct in6_addr *dst, 
                        struct icmp6_hdr *icmp6, size_t len) {
    char buf[BUFFER_SIZE];
    struct ip6_hdr_pseudo {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t length;
        uint8_t zero[3];
        uint8_t next_header;
    } *pseudo;
    
    pseudo = (struct ip6_hdr_pseudo *)buf;
    memcpy(&pseudo->src, src, sizeof(struct in6_addr));
    memcpy(&pseudo->dst, dst, sizeof(struct in6_addr));
    pseudo->length = htonl(len);
    memset(pseudo->zero, 0, 3);
    pseudo->next_header = IPPROTO_ICMPV6;
    
    memcpy(buf + sizeof(struct ip6_hdr_pseudo), icmp6, len);
    
    return checksum((uint16_t *)buf, sizeof(struct ip6_hdr_pseudo) + len);
}

// ================= Network Functions =================

int create_send_socket() {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket(IPPROTO_RAW)"); return -1; }
    int on = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IPV6_HDRINCL"); close(sock); return -1;
    }
    return sock;
}

int create_recv_socket() {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0) { perror("socket(IPPROTO_ICMPV6)"); return -1; }
    int rcvbuf_size = 2 * 1024 * 1024; // 2MB buffer
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
    return sock;
}

// Construct IPv6-in-IPv6 Packet
int build_packet(uint8_t *packet, int target_idx, int inner_ttl, uint16_t icmp_id, uint16_t icmp_seq) {
    struct ip6_hdr *outer_ip6 = (struct ip6_hdr *)packet;
    struct ip6_hdr *inner_ip6 = (struct ip6_hdr *)(packet + sizeof(struct ip6_hdr));
    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(packet + 2 * sizeof(struct ip6_hdr));
    
    // 1. Outer IPv6 Header: Local -> Tunnel Node
    memset(outer_ip6, 0, sizeof(struct ip6_hdr));
    outer_ip6->ip6_flow = htonl(0x60000000);
    outer_ip6->ip6_plen = htons(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr));
    outer_ip6->ip6_nxt = IPPROTO_IPV6; // 41 (Encapsulation)
    outer_ip6->ip6_hops = 64;          // Outer TTL sufficient to reach tunnel node
    memcpy(&outer_ip6->ip6_src, &local_addr, sizeof(struct in6_addr));
    memcpy(&outer_ip6->ip6_dst, &targets[target_idx].tunnel_addr, sizeof(struct in6_addr));
    
    // 2. Inner IPv6 Header: Local -> Receiver (Traceroute Core)
    memset(inner_ip6, 0, sizeof(struct ip6_hdr));
    inner_ip6->ip6_flow = htonl(0x60000000);
    inner_ip6->ip6_plen = htons(sizeof(struct icmp6_hdr));
    inner_ip6->ip6_nxt = IPPROTO_ICMPV6;
    
    // === Key Point: Inner Hop Limit ===
    inner_ip6->ip6_hops = inner_ttl; 
    
    // Inner source must be Local, so Time Exceeded returns to us
    memcpy(&inner_ip6->ip6_src, &local_addr, sizeof(struct in6_addr));
    memcpy(&inner_ip6->ip6_dst, &final_dest_addr, sizeof(struct in6_addr));
    
    // 3. ICMPv6 Echo Request
    memset(icmp6, 0, sizeof(struct icmp6_hdr));
    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id = htons(icmp_id);
    icmp6->icmp6_seq = htons(icmp_seq);
    
    // Checksum calculated over inner pseudo-header
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_cksum = icmp6_checksum(&local_addr, &final_dest_addr, icmp6, sizeof(struct icmp6_hdr));
    
    return sizeof(struct ip6_hdr) * 2 + sizeof(struct icmp6_hdr);
}

int send_probe(int target_idx, int ttl, uint16_t id, uint16_t seq) {
    uint8_t packet[BUFFER_SIZE];
    int packet_len = build_packet(packet, target_idx, ttl, id, seq);
    
    struct sockaddr_in6 dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    memcpy(&dest_addr.sin6_addr, &targets[target_idx].tunnel_addr, sizeof(struct in6_addr));
    
    ssize_t sent = sendto(send_sockfd, packet, packet_len, 0, 
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    if (sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // perror("sendto"); 
        }
        return -1;
    }
    return 0;
}

// ================= Thread Functions =================

// Send Thread
void *send_thread(void *arg) {
    uint16_t base_id = getpid() & 0xFFFF;
    printf("Send thread started. Targets: %d, Max Hops: %d\n", target_count, MAX_HOPS);
    
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        int packets_sent_this_round = 0;
        
        for (int i = 0; i < target_count; i++) {
            // If target reached, skip subsequent TTLs
            pthread_mutex_lock(&target_mutex);
            int is_finished = targets[i].reached_dest;
            pthread_mutex_unlock(&target_mutex);
            
            if (is_finished) continue;

            for (int seq = 0; seq < PACKETS_PER_HOP; seq++) {
                
                uint16_t pkt_id = (base_id + i) & 0xFFFF; 
                uint16_t pkt_seq = (ttl << 8) | seq; 
                
                pthread_mutex_lock(&record_mutex);
                if (packet_count < MAX_PACKET_RECORDS) {
                    get_current_time(&packet_records[packet_count].send_time);
                    packet_records[packet_count].id = pkt_id;
                    packet_records[packet_count].seq = pkt_seq;
                    packet_records[packet_count].target_index = i;
                    packet_records[packet_count].ttl = ttl;
                    packet_records[packet_count].matched = 0;
                    
                    add_to_hash_table(pkt_id, pkt_seq, packet_count);
                    packet_count++;
                } else {
                    pthread_mutex_unlock(&record_mutex);
                    goto end_send; // Records full, abort
                }
                pthread_mutex_unlock(&record_mutex);
                
                send_probe(i, ttl, pkt_id, pkt_seq);
                packets_sent_this_round++;
            }
            
            // Minimal flow control
            if (packets_sent_this_round % 100 == 0) usleep(1000);
        }
        
        printf("Finished sending round TTL=%d\n", ttl);
        usleep(50000); // Wait 50ms between TTL rounds
    }
    
end_send:
    // === Core Logic: Set Done Flag & Record Time ===
    pthread_mutex_lock(&target_mutex);
    send_done = 1;
    send_finish_time = time(NULL);
    pthread_mutex_unlock(&target_mutex);
    printf("Send thread completed. Starting %d-second receive timeout.\n", TIMEOUT_SEC);
    
    return NULL;
}

// Receive Thread
void *receive_thread(void *arg) {
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in6 src_addr;
    socklen_t addr_len = sizeof(src_addr);
    fd_set readfds;
    struct timeval tv;
    
    printf("Receive thread started...\n");
    
    // Loop until sending finishes + TIMEOUT
    while (1) {
        
        if (send_done) {
            time_t now = time(NULL);
            time_t elapsed = now - send_finish_time;
            
            if (elapsed >= TIMEOUT_SEC) {
                printf("Receive thread timed out after %ld seconds.\n", elapsed);
                break; // Timeout exit
            }
            
            time_t remaining = TIMEOUT_SEC - elapsed;
            tv.tv_sec = remaining > 1 ? 1 : remaining;
            tv.tv_usec = 0;
            
        } else {
            // Sending active, listen in 1s chunks
            tv.tv_sec = 1; 
            tv.tv_usec = 0;
        }
        
        FD_ZERO(&readfds);
        FD_SET(recv_sockfd, &readfds);
        
        int ret = select(recv_sockfd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (ret == 0) {
            continue; // Timeout
        }
        
        if (FD_ISSET(recv_sockfd, &readfds)) {
            ssize_t recv_len = recvfrom(recv_sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&src_addr, &addr_len);
            if (recv_len < sizeof(struct icmp6_hdr)) continue;
            
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
            uint16_t orig_id = 0;
            uint16_t orig_seq = 0;
            int type = icmp6->icmp6_type;
            
            if (type == ICMP6_TIME_EXCEEDED) {
                size_t min_len = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
                if (recv_len < min_len) continue;
                
                uint8_t *payload = buffer + sizeof(struct icmp6_hdr);
                struct ip6_hdr *orig_ip6 = (struct ip6_hdr *)payload;
                
                if (orig_ip6->ip6_nxt == IPPROTO_ICMPV6) {
                    struct icmp6_hdr *orig_icmp = (struct icmp6_hdr *)(payload + sizeof(struct ip6_hdr));
                    orig_id = ntohs(orig_icmp->icmp6_id);
                    orig_seq = ntohs(orig_icmp->icmp6_seq);
                } else continue;
                
            } else if (type == ICMP6_ECHO_REPLY) {
                if (memcmp(&src_addr.sin6_addr, &final_dest_addr, sizeof(struct in6_addr)) == 0) {
                    orig_id = ntohs(icmp6->icmp6_id);
                    orig_seq = ntohs(icmp6->icmp6_seq);
                } else {
                    continue; 
                }
            } else {
                continue;
            }
            
            // Lookup Record
            int record_idx = find_in_hash_table(orig_id, orig_seq);
            if (record_idx >= 0) {
                if (packet_records[record_idx].matched == 0) {
                    struct timespec recv_time;
                    get_current_time(&recv_time);
                    
                    double rtt = time_diff_ms(&packet_records[record_idx].send_time, &recv_time);
                    int target_idx = packet_records[record_idx].target_index;
                    int ttl = packet_records[record_idx].ttl;
                    
                    packet_records[record_idx].matched = 1;
                    
                    pthread_mutex_lock(&target_mutex);
                    if (type == ICMP6_ECHO_REPLY) {
                        // Update if first reply or lower RTT
                        if (!targets[target_idx].reached_dest || rtt < targets[target_idx].final_rtt) {
                            targets[target_idx].final_rtt = rtt;
                            targets[target_idx].reached_dest = 1;
                            targets[target_idx].best_ttl = ttl;
                        }
                        
                        // Mark as reached to skip future sends in send_thread
                        targets[target_idx].reached_dest = 1;
                    }
                    pthread_mutex_unlock(&target_mutex);
                    
                    if (type == ICMP6_ECHO_REPLY) {
                        // Debug: Successfully reached receiver via tunnel
                        // printf("Target [%d] Reached via TTL=%d, RTT=%.2f ms\n", target_idx, ttl, rtt);
                    }
                }
            }
        }
    }
    printf("Receive thread finished.\n");
    return NULL;
}

// ================= File I/O =================

int read_targets_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) { perror("fopen targets"); return -1; }
    
    char line[INET6_ADDRSTRLEN + 10]; 
    target_count = 0;
    
    while (fgets(line, sizeof(line), file) && target_count < MAX_TARGETS) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;
        
        if (parse_ipv6_addr(line, &targets[target_count].tunnel_addr) == 1) {
            strcpy(targets[target_count].tunnel_addr_str, line);
            targets[target_count].final_rtt = -1.0;
            targets[target_count].reached_dest = 0;
            targets[target_count].best_ttl = 0;
            target_count++;
        } else {
            fprintf(stderr, "Skipping invalid address: %s\n", line);
        }
    }
    
    fclose(file);
    return target_count;
}

int write_results_to_file(const char *filename, const char *final_dest_str) {
    FILE *file = fopen(filename, "w");
    if (!file) { perror("fopen output"); return -1; }
    
    int success_count = 0;
    
    for (int i = 0; i < target_count; i++) {
        // Output Format: TunnelNode Receiver RTT
        if (targets[i].reached_dest) {
            fprintf(file, "%s %s %.3f\n", 
                    targets[i].tunnel_addr_str, 
                    final_dest_str, 
                    targets[i].final_rtt);
            success_count++;
        } else {
            fprintf(file, "%s %s -1.000\n", 
                    targets[i].tunnel_addr_str, 
                    final_dest_str);
        }
    }
    
    fclose(file);
    printf("Results written to %s. (Success: %d/%d)\n", filename, success_count, target_count);
    return 0;
}

// ================= Main =================

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <local_ipv6> <targets_file> <receiver_ipv6> <output_file>\n", argv[0]);
        return 1;
    }
    
    // 1. Parse Local IPv6
    if (parse_ipv6_addr(argv[1], &local_addr) != 1) {
        fprintf(stderr, "Invalid local IPv6: %s\n", argv[1]); return 1;
    }
    
    // 2. Read Tunnel Nodes
    if (read_targets_from_file(argv[2]) <= 0) {
        fprintf(stderr, "No targets loaded.\n"); return 1;
    }
    printf("Loaded %d tunnel targets.\n", target_count);
    
    // 3. Parse Receiver IPv6
    if (parse_ipv6_addr(argv[3], &final_dest_addr) != 1) {
        fprintf(stderr, "Invalid receiver IPv6: %s\n", argv[3]); return 1;
    }
    
    // 4. Create Sockets
    send_sockfd = create_send_socket();
    recv_sockfd = create_recv_socket();
    if (send_sockfd < 0 || recv_sockfd < 0) return 1;
    
    // Set Non-blocking Send
    int flags = fcntl(send_sockfd, F_GETFL, 0);
    fcntl(send_sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // 5. Start Threads
    pthread_t send_tid, recv_tid;
    
    // Start Receiver first
    if (pthread_create(&recv_tid, NULL, receive_thread, NULL) != 0) return 1;
    usleep(100000); // 100ms delay to ensure receiver is up
    if (pthread_create(&send_tid, NULL, send_thread, NULL) != 0) return 1;
    
    // 6. Wait for Threads
    pthread_join(send_tid, NULL);
    pthread_join(recv_tid, NULL);
    
    // 7. Write Results
    write_results_to_file(argv[4], argv[3]);
    
    // 8. Cleanup
    cleanup_hash_table();
    close(send_sockfd);
    close(recv_sockfd);
    
    return 0;
}