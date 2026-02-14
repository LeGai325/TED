#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>
#include <stdatomic.h>

// --- 配置参数 ---
#define SEND_THREADS 10     // 发送线程数
#define TEST_COUNT 3        // 每个节点测试次数
#define WAIT_TIME_SEC 3     // 发送完后的等待时间
#define MAX_SEQ 65536       // 序列号回绕上限
#define MAX_TARGETS 210000  // 最大目标数

// --- 数据结构 ---

typedef struct {
    char ip_str[INET6_ADDRSTRLEN];
    struct in6_addr addr;       // 原始目标地址
    struct in6_addr inner_src;  // 发送时伪造的内层源地址 (Target + 1)
    long rtt_us[TEST_COUNT];    // 结果记录
} Target;

typedef struct {
    Target *target_ptr;      // 指向目标对象的指针
    int ping_index;          // 第几次测试 (0-2)
    struct timeval send_time;
    uint16_t seq;            // 序列号校验
    atomic_int valid;        // 有效位
} PacketRecord;

// --- 全局变量 ---
Target *targets;
int total_targets = 0;
PacketRecord records[MAX_SEQ];

struct in6_addr prober_addr;
int sock_send, sock_recv;
uint16_t global_id;

// 原子计数器
atomic_int current_target_idx = 0;
atomic_uint global_seq_counter = 0;
atomic_long matched_count = 0; // 成功匹配的数量
atomic_long total_sent_packets = 0;

volatile int keep_receiving = 1;

// --- 辅助工具函数 ---

long time_diff_us(struct timeval start, struct timeval end) {
    return (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
}

// 校验和计算
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    unsigned short oddbyte;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (short)~sum;
}

unsigned short icmp6_checksum(struct ip6_hdr *ip6, struct icmp6_hdr *icmp6, int icmp_len) {
    char buf[2048];
    struct {
        struct in6_addr src, dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next;
    } psh;
    psh.src = ip6->ip6_src;
    psh.dst = ip6->ip6_dst;
    psh.len = htonl(icmp_len);
    memset(psh.zero, 0, 3);
    psh.next = IPPROTO_ICMPV6;

    int psh_len = sizeof(psh);
    memcpy(buf, &psh, psh_len);
    memcpy(buf + psh_len, icmp6, icmp_len);
    return calculate_checksum((unsigned short *)buf, psh_len + icmp_len);
}

// --- 核心地址操作逻辑 ---

// 发送逻辑: 最后一字节 + 1 mod 255
void generate_inner_src(struct in6_addr *target, struct in6_addr *result) {
    *result = *target;
    uint8_t last = result->s6_addr[15];
    result->s6_addr[15] = (last + 1) % 255; 
}

// 接收反向逻辑: 还原原始地址
// 算法逆推: 
// if current == 0, original was 254 (because (254+1)%255 = 0)
// else original = current - 1
void recover_original_target(struct in6_addr *received_inner_src, struct in6_addr *recovered) {
    *recovered = *received_inner_src;
    uint8_t current = recovered->s6_addr[15];
    
    if (current == 0) {
        recovered->s6_addr[15] = 254;
    } else {
        recovered->s6_addr[15] = current - 1;
    }
}

// 比较两个 IPv6 地址是否相等
int is_addr_equal(struct in6_addr *a, struct in6_addr *b) {
    return memcmp(a, b, sizeof(struct in6_addr)) == 0;
}

// --- 接收线程 ---
void *receiver_thread(void *arg) {
    char buffer[2048];
    struct sockaddr_in6 src_addr;
    socklen_t addr_len = sizeof(src_addr);
    struct timeval recv_tv;
    struct in6_addr recovered_addr;

    while (keep_receiving) {
        fd_set readfds;
        struct timeval timeout = {0, 50000}; // 50ms
        FD_ZERO(&readfds);
        FD_SET(sock_recv, &readfds);

        int ready = select(sock_recv + 1, &readfds, NULL, NULL, &timeout);
        if (ready <= 0) continue;

        int len = recvfrom(sock_recv, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
        if (len < 0) continue;
        gettimeofday(&recv_tv, NULL);

        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;

        // 1. 基本检查: 必须是 Echo Request 且 ID 匹配
        if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST && ntohs(icmp6->icmp6_id) == global_id) {
            uint16_t seq = ntohs(icmp6->icmp6_seq);
            PacketRecord *rec = &records[seq];

            // 2. 检查记录是否有效
            if (atomic_load(&rec->valid) && rec->seq == seq && rec->target_ptr != NULL) {
                
                // 3. 执行反向操作: 从收到的源地址还原原本的目标地址
                // src_addr.sin6_addr 是数据包的 IPv6 源地址 (即隧道转发回来的 Inner Src)
                recover_original_target(&src_addr.sin6_addr, &recovered_addr);

                // 4. 地址匹配验证
                if (is_addr_equal(&recovered_addr, &rec->target_ptr->addr)) {
                    // 匹配成功！
                    atomic_fetch_add(&matched_count, 1);
                    
                    int idx = rec->ping_index;
                    // 如果该次测试尚未记录结果，则写入
                    if (rec->target_ptr->rtt_us[idx] == -1) {
                        long rtt = time_diff_us(rec->send_time, recv_tv);
                        rec->target_ptr->rtt_us[idx] = rtt;
                    }
                } else {
                    // Seq 匹配但 IP 还原后不匹配，可能是序列号冲突或恶意包，忽略
                }
            }
        }
    }
    return NULL;
}

// --- 发送线程 ---
void *sender_thread(void *arg) {
    char buffer[1500];
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;

    while (1) {
        int idx = atomic_fetch_add(&current_target_idx, 1);
        if (idx >= total_targets) break;

        Target *t = &targets[idx];
        dest.sin6_addr = t->addr; // 外部 IPv6 目的地址 (Tunnel Endpoint)

        for (int i = 0; i < TEST_COUNT; i++) {
            unsigned int raw_seq = atomic_fetch_add(&global_seq_counter, 1);
            uint16_t seq = raw_seq % MAX_SEQ;

            PacketRecord *rec = &records[seq];
            rec->target_ptr = t;
            rec->ping_index = i;
            rec->seq = seq;
            gettimeofday(&rec->send_time, NULL);
            atomic_store(&rec->valid, 1);

            // 构造包结构: [Inner IP] [Fragment Header] [ICMPv6 Header]
            memset(buffer, 0, sizeof(buffer));
            
            // 指针定位
            struct ip6_hdr *inner_ip6 = (struct ip6_hdr *)buffer;
            struct ip6_frag *inner_frag = (struct ip6_frag *)(buffer + sizeof(struct ip6_hdr));
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(buffer + sizeof(struct ip6_hdr) + sizeof(struct ip6_frag));

            // 1. Inner IP Header
            inner_ip6->ip6_flow = htonl(0x60000000);
            // 负载长度 = 分片头长度 + ICMP头长度
            inner_ip6->ip6_plen = htons(sizeof(struct ip6_frag) + sizeof(struct icmp6_hdr));
            inner_ip6->ip6_nxt = IPPROTO_FRAGMENT; // Next Header = 44
            inner_ip6->ip6_hlim = 64;
            inner_ip6->ip6_src = t->inner_src; 
            inner_ip6->ip6_dst = prober_addr;

            // 2. Fragment Header
            inner_frag->ip6f_nxt = IPPROTO_ICMPV6; // Next Header = 58
            inner_frag->ip6f_reserved = 0;
            inner_frag->ip6f_offlg = 0; // Offset=0, M=0 (Atomic Fragment)
            inner_frag->ip6f_ident = htonl(global_id + seq); // 唯一标识

            // 3. ICMPv6 Header
            icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6->icmp6_code = 0;
            icmp6->icmp6_id = htons(global_id);
            icmp6->icmp6_seq = htons(seq);
            icmp6->icmp6_cksum = 0;
            
            // 计算校验和时，只传入 ICMP 部分的长度
            // icmp6_checksum 函数内部会构建伪首部，NextHeader 填 58 (ICMPv6)
            icmp6->icmp6_cksum = icmp6_checksum(inner_ip6, icmp6, sizeof(struct icmp6_hdr));

            int len = sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + sizeof(struct icmp6_hdr);
            
            // 发送 (Kernel 自动添加 Outer IPv6 Header)
            if (sendto(sock_send, buffer, len, 0, (struct sockaddr *)&dest, sizeof(dest)) > 0) {
                atomic_fetch_add(&total_sent_packets, 1);
            }
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <Local IPv6> <Input File> <Output File>\n", argv[0]);
        return -1;
    }

    if (inet_pton(AF_INET6, argv[1], &prober_addr) != 1) {
        fprintf(stderr, "Error: Invalid Local IPv6\n");
        return -1;
    }

    srand(time(NULL));
    global_id = rand() & 0xFFFF;

    // 1. 读取目标
    printf("[Init] Reading targets from %s...\n", argv[2]);
    FILE *fp = fopen(argv[2], "r");
    if (!fp) { perror("fopen input"); return -1; }

    targets = (Target *)malloc(sizeof(Target) * MAX_TARGETS);
    char line[256];
    while (fgets(line, sizeof(line), fp) && total_targets < MAX_TARGETS) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) < 3) continue;

        Target *t = &targets[total_targets];
        strncpy(t->ip_str, line, INET6_ADDRSTRLEN);
        if (inet_pton(AF_INET6, line, &t->addr) == 1) {
            generate_inner_src(&t->addr, &t->inner_src);
            for(int k=0; k<TEST_COUNT; k++) t->rtt_us[k] = -1;
            total_targets++;
        }
    }
    fclose(fp);
    printf("[Init] Loaded %d targets.\n", total_targets);

    // 2. 初始化 Socket
    if ((sock_send = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6)) < 0) {
        perror("Socket Send"); return -1;
    }
    int sndbuf = 2 * 1024 * 1024;
    setsockopt(sock_send, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    if ((sock_recv = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
        perror("Socket Recv"); return -1;
    }
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(sock_recv, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // 3. 启动线程
    pthread_t recv_tid;
    pthread_create(&recv_tid, NULL, receiver_thread, NULL);

    pthread_t send_tids[SEND_THREADS];
    printf("[Run] Starting %d sender threads...\n", SEND_THREADS);
    
    struct timeval start, end;
    gettimeofday(&start, NULL);

    for (int i = 0; i < SEND_THREADS; i++) {
        pthread_create(&send_tids[i], NULL, sender_thread, NULL);
    }

    for (int i = 0; i < SEND_THREADS; i++) {
        pthread_join(send_tids[i], NULL);
    }
    
    gettimeofday(&end, NULL);
    double duration = time_diff_us(start, end) / 1000000.0;
    
    printf("[Run] Sending complete. Time: %.2fs. Packets sent: %ld.\n", duration, atomic_load(&total_sent_packets));
    printf("[Run] Waiting %d seconds for stragglers...\n", WAIT_TIME_SEC);
    
    sleep(WAIT_TIME_SEC);
    keep_receiving = 0;
    pthread_join(recv_tid, NULL);

    // 4. 统计与输出
    long final_matches = atomic_load(&matched_count);
    printf("------------------------------------------------\n");
    printf("Summary:\n");
    printf("  Targets Loaded : %d\n", total_targets);
    printf("  Packets Sent   : %ld\n", atomic_load(&total_sent_packets));
    printf("  Packets Matched: %ld\n", final_matches);
    printf("------------------------------------------------\n");
    printf("[Save] Writing results to %s...\n", argv[3]);

    FILE *fp_out = fopen(argv[3], "w");
    if (!fp_out) { perror("fopen output"); return -1; }

    for (int i = 0; i < total_targets; i++) {
        double total_rtt = 0;
        int count = 0;
        for (int k = 0; k < TEST_COUNT; k++) {
            if (targets[i].rtt_us[k] != -1) {
                total_rtt += targets[i].rtt_us[k];
                count++;
            }
        }
        if (count > 0) {
            double avg = (total_rtt / count) / 1000.0;
            fprintf(fp_out, "%s %.3f ms\n", targets[i].ip_str, avg);
        } else {
            fprintf(fp_out, "%s Timeout\n", targets[i].ip_str);
        }
    }
    fclose(fp_out);
    
    free(targets);
    close(sock_send);
    close(sock_recv);
    printf("[Done] All tasks finished.\n");

    return 0;
}
