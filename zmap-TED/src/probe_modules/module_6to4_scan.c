// probe module for performing 6to4 scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "logger.h"
#include "validate.h"

probe_module_t module_6to4_scan;
static size_t payload_len = 5;
static size_t scan_type = 0;       //special type code

/*
#define ASMAP_LEN 222217

typedef struct {
    unsigned int low;
    unsigned int high;
    unsigned int prefix1;
    unsigned int prefix2;
} Asmap;

Asmap asmap[ASMAP_LEN];     //global array

void load_asmap() {
    FILE* file = fopen("asmap.ini", "r");
    int index = 0;
    while (index < ASMAP_LEN && fscanf(file, "%u %u %u %u", &asmap[index].low, &asmap[index].high, &asmap[index].prefix1, &asmap[index].prefix2) == 4) {
        index++;
    }
    fclose(file);
}
*/

static int module_6to4_scan_init_perthread(void* buf, macaddr_t *src, macaddr_t *gw,
                                      UNUSED port_h_t dst_port,
                                      UNUSED void **arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
    //load_asmap();       //read asmap

    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    uint16_t len = htons(sizeof(struct ip) +sizeof(struct ip6_hdr) +sizeof(struct icmp6_hdr) +payload_len);
    make_ip_header(ip_header, IPPROTO_IPV6, len);

    struct ip6_hdr *ip6_header = (struct ip6_hdr *) (&ip_header[1]);
    ip6_header->ip6_flow = htonl(0x60000000);
    ip6_header->ip6_plen = htons(sizeof(struct icmp6_hdr) +payload_len);
    ip6_header->ip6_nxt = IPPROTO_ICMPV6;
    ip6_header->ip6_hops = MAXTTL;

    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6_header[1]);
    icmp6_header->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_header->icmp6_code = 0;
    icmp6_header->icmp6_cksum = 0;
    icmp6_header->icmp6_data32[0] = 0;

    return EXIT_SUCCESS;
}

static int module_6to4_scan_make_packet(void *buf, size_t *buf_len,
                                   ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
                                   UNUSED uint32_t *validation, UNUSED int probe_num, 
                                   UNUSED void *arg)
{
    struct ether_header *eth_header = (struct ether_header *)buf;
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&ip_header[1]);
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6_header[1]);
    char *payload = (char *)(&icmp6_header[1]);

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_ttl = ttl;

    /*
    int dst_ip_big = htonl(dst_ip);     //to big-endian, because ipranges [low, high) in asmap are big-endian
    int left = 0;
    int right = ASMAP_LEN - 1;
    int mid = 0;
    while (left <= right) {         //binary search
        mid = (left + right) / 2;
        if (asmap[mid].low <= dst_ip_big && dst_ip_big < asmap[mid].high) {
            break;
        } else if (dst_ip_big < asmap[mid].low) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    ip6_header->ip6_src.s6_addr32[0] = asmap[mid].prefix1;      //but prefixes in asmap are small-endian, and well ordered
    ip6_header->ip6_src.s6_addr32[1] = asmap[mid].prefix2;
    ip6_header->ip6_src.s6_addr32[2] = htonl(0x00000000);
    ip6_header->ip6_src.s6_addr32[3] = htonl(0x00001234);

    ip6_header->ip6_dst.s6_addr16[0] = htons(0x2402);
    ip6_header->ip6_dst.s6_addr16[1] = htons(0xf000);
    ip6_header->ip6_dst.s6_addr16[2] = htons(0x0006);
    ip6_header->ip6_dst.s6_addr16[3] = htons(0x1e00);
    ip6_header->ip6_dst.s6_addr16[4] = htons(0x0000);
    ip6_header->ip6_dst.s6_addr16[5] = htons(0x0000);
    ip6_header->ip6_dst.s6_addr16[6] = htons(0x0000);
    ip6_header->ip6_dst.s6_addr16[7] = htons(0x0236);
    */

    ip6_header->ip6_src.s6_addr16[0] = htons(0x2002);
    ip6_header->ip6_src.s6_addr16[1] = src_ip & 0xffff;
    ip6_header->ip6_src.s6_addr16[2] = (src_ip >> 16) & 0xffff;
    ip6_header->ip6_src.s6_addr16[3] = htons(0x0000);
    ip6_header->ip6_src.s6_addr16[4] = htons(0x0000);
    ip6_header->ip6_src.s6_addr16[5] = htons(0x0000);
    ip6_header->ip6_src.s6_addr16[6] = htons(0x0000);
    ip6_header->ip6_src.s6_addr16[7] = htons(0x0001);

    ip6_header->ip6_dst.s6_addr16[0] = htons(0x2002);
    ip6_header->ip6_dst.s6_addr16[1] = dst_ip & 0xffff;
    ip6_header->ip6_dst.s6_addr16[2] = (dst_ip >> 16) & 0xffff;
    ip6_header->ip6_dst.s6_addr16[3] = htons(0x0000);
    ip6_header->ip6_dst.s6_addr16[4] = htons(0x0000);
    ip6_header->ip6_dst.s6_addr16[5] = htons(0x0000);
    ip6_header->ip6_dst.s6_addr16[6] = dst_ip & 0xffff;
    ip6_header->ip6_dst.s6_addr16[7] = (dst_ip >> 16) & 0xffff;

    payload[0] = scan_type;
    payload[1] = dst_ip & 0xff;
    payload[2] = (dst_ip >> 8) & 0xff;
    payload[3] = (dst_ip >> 16) & 0xff;
    payload[4] = (dst_ip >> 24) & 0xff;

    struct icmp6_cksum {
        struct in6_addr ip6_src;
        struct in6_addr ip6_dst;
        uint32_t ip6_paylen;
        uint16_t zeros_part1;
        uint8_t zeros_part2;
        uint8_t ip6_next;
        struct icmp6_hdr icmp6_header;
        char payload[5];
    } cksum;
    memset(&cksum, 0, sizeof(struct icmp6_cksum));
    memcpy(&cksum.ip6_src, &ip6_header->ip6_src, sizeof(struct in6_addr));
    memcpy(&cksum.ip6_dst, &ip6_header->ip6_dst, sizeof(struct in6_addr));
    cksum.ip6_paylen = ip6_header->ip6_plen;
    cksum.ip6_next = ip6_header->ip6_nxt;
    cksum.icmp6_header.icmp6_type = ICMP6_ECHO_REQUEST;
    cksum.icmp6_header.icmp6_code = 0;
    cksum.icmp6_header.icmp6_cksum = 0;
    cksum.icmp6_header.icmp6_data32[0] = 0;
    memcpy(cksum.payload, payload, payload_len);
    icmp6_header->icmp6_cksum = icmp_checksum((unsigned short *)&cksum, sizeof(struct icmp6_cksum));

    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

    *buf_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + payload_len;

    return EXIT_SUCCESS;
}

static void module_6to4_scan_print_packet(FILE *fp, void *packet)
{
    struct ether_header *ethh = (struct ether_header *)packet;
    struct ip *iph = (struct ip *)(&ethh[1]);
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(&iph[1]);
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6h[1]);

    fprintf(fp,
            "icmpv6 { type: %u | code: %u | checksum: %#04X } \n",
            icmp6_header->icmp6_type, icmp6_header->icmp6_code, ntohs(icmp6_header->icmp6_cksum));
    fprintf_ipv6_header(fp, ip6h);
    fprintf_ip_header(fp, iph);
    fprintf_eth_header(fp, ethh);
    fprintf(fp, PRINT_PACKET_SEP);
}

static int module_6to4_scan_validate_packet(const struct ip *ip_hdr, uint32_t len,
                                       UNUSED uint32_t *src_ip, UNUSED uint32_t *validation)
{
    if (ip_hdr->ip_p != IPPROTO_IPV6) {
        return PACKET_INVALID;
    }
    if ((4 * ip_hdr->ip_hl + sizeof(struct ip6_hdr)) + sizeof(struct icmp6_hdr) > len) {
        return PACKET_INVALID;
    }
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
    if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
        return PACKET_INVALID;
    }
    struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *) (&ip6_hdr[1]);
    if (icmp6_hdr->icmp6_type != ICMP6_ECHO_REPLY) {
        return PACKET_INVALID;
    }
    char *payload = (char *)(&icmp6_hdr[1]);
    if (payload[0] != scan_type) {
        return PACKET_INVALID;
    }
    return PACKET_VALID;
}

static void module_6to4_scan_process_packet(const u_char *packet,
                                       UNUSED uint32_t len,
                                       fieldset_t *fs,
                                       UNUSED uint32_t *validation,
                                       UNUSED struct timespec ts)
{
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
    struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *) (&ip6_hdr[1]);
    fs_add_uint64(fs, "type", icmp6_hdr->icmp6_type);
    fs_add_uint64(fs, "code", icmp6_hdr->icmp6_code);
    fs_add_string(fs, "saddr", make_ip_str(ip_hdr->ip_src.s_addr), 1);
    fs_add_constchar(fs, "classification", "6to4 reply");
    fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
    {.name = "type", .type = "int", .desc = "icmp message type"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "saddr", .type = "string", .desc = "ipv4 src address of reply packet"},
    {.name = "classification", .type = "string", .desc = "probe module classification"},
    {.name = "success", .type = "bool", .desc = "did probe module classify response as success"}
};

probe_module_t module_6to4_scan = {
    .name = "6to4_scan",
    .max_packet_length = 88,    //20 IP header + 40 IPv6 header + 8 ICMPv6 header + 20 payload
    .pcap_filter = "ip",
    .pcap_snaplen =  150,
    .port_args = 0,
    .global_initialize = NULL,
    .thread_initialize = &module_6to4_scan_init_perthread,
    .make_packet = &module_6to4_scan_make_packet,
    .print_packet = &module_6to4_scan_print_packet,
    .process_packet = &module_6to4_scan_process_packet,
    .validate_packet = &module_6to4_scan_validate_packet,
    .close = NULL,
    .helptext =    "Probe module that sends 6to4 protocol packets to detect 6to4 relay.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = 5
};
