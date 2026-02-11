/* heavily copied from module_udp.c */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/blocklist.h"
#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "../../lib/logger.h"
#include "../../lib/xalloc.h"
#include "gue.h"

#include "../state.h"

#include "probe_modules.h"
#include "packet.h"


#define MAX_UDP_PAYLOAD_LEN 200
#define ICMP_UNREACH_HEADER_SIZE 8
#define UNUSED __attribute__((unused))


static int num_ports;

probe_module_t module_gue;


int gue_global_initialize(struct state_conf *conf)
{
	return EXIT_SUCCESS;
}


int gue_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
			UNUSED port_h_t dst_port, UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct guehdr) + sizeof(struct ip) + sizeof(struct icmp));
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr *)(&ip_header[1]);
	len = sizeof(struct udphdr) + sizeof(struct guehdr) + sizeof(struct ip) + sizeof(struct icmp);
	make_udp_header(udp_header, zconf.target_port, len);

	struct guehdr *gue_header = (struct guehdr *)(&udp_header[1]);
	len = htons(sizeof(struct guehdr) + sizeof(struct ip) + sizeof(struct icmp));
	make_gue_header(gue_header, IPPROTO_IPIP, len);

	struct ip *ip_header2 = (struct ip *)(&gue_header[1]);
	len = htons(sizeof(struct ip) +  sizeof(struct icmp));
	make_ip_header(ip_header2, IPPROTO_ICMP, len);

	struct icmp *icmp_hdr = (struct icmp *)(&ip_header2[1]);
	make_icmp_header2(icmp_hdr, ICMP_ECHOREPLY);


	return EXIT_SUCCESS;
}

int gue_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
		     ipaddr_n_t dst_ip, UNUSED uint8_t ttl,
		     uint32_t *validation, int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct udphdr *udp_header = (struct udphdr *) (&ip_header[1]);
	struct guehdr *gue_header = (struct guehdr *) (&udp_header[1]);
	struct ip *ip_header2 = (struct ip *)(&gue_header[1]);
	struct icmp *icmp_header = (struct icmp *) (&ip_header2[1]);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	ip_header2->ip_src.s_addr = dst_ip;
	ip_header2->ip_dst = ((struct in_addr *)arg)[0]; //external IP

	if (ip_header2->ip_dst.s_addr == INADDR_ANY)
	{
		ip_header2->ip_dst.s_addr = src_ip;
	}

	ip_header2->ip_sum = 0;
	ip_header2->ip_sum = zmap_ip_checksum((unsigned short *)ip_header2);
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	icmp_header->icmp_id = validation[1] & 0xFFFF;
	icmp_header->icmp_seq = validation[2] & 0xFFFF;

	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum =
	    icmp_checksum((unsigned short *)icmp_header, ICMP_MINLEN);

	// Output the total length of the packet
	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) +
		sizeof(struct udphdr) + sizeof(struct guehdr) + sizeof(struct ip) + sizeof(struct icmp);
	return EXIT_SUCCESS;
}

void gue_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct ip *iph2 = (struct ip *)&iph[1];
	struct udphdr *udph = (struct udphdr *)(&iph2[1]);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport), ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ip_header(fp, iph2);
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void gue_process_packet(const u_char *packet, UNUSED uint32_t len,
			 fieldset_t *fs, UNUSED uint32_t *validation,
			 UNUSED const struct timespec ts)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct icmp *icmp_hdr = (struct icmp *)(&ip_hdr[1]);
	fs_add_uint64(fs, "type", icmp_hdr->icmp_type);
	fs_add_uint64(fs, "code", icmp_hdr->icmp_code);
	fs_add_uint64(fs, "icmp_id", ntohs(icmp_hdr->icmp_id));
	fs_add_uint64(fs, "seq", ntohs(icmp_hdr->icmp_seq));

	switch (icmp_hdr->icmp_type) {
	case ICMP_ECHOREPLY:
		fs_add_string(fs, "classification", (char *)"echoreply", 0);
		fs_add_uint64(fs, "success", 1);
		break;
	case ICMP_UNREACH:
		fs_add_string(fs, "classification", (char *)"unreach", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	case ICMP_SOURCEQUENCH:
		fs_add_string(fs, "classification", (char *)"sourcequench", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	case ICMP_REDIRECT:
		fs_add_string(fs, "classification", (char *)"redirect", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	case ICMP_TIME_EXCEEDED:
		fs_add_string(fs, "classification", (char *)"timxceed", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	default:
		fs_add_string(fs, "classification", (char *)"other", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	}
}

int gue_validate_packet(const struct ip *ip_hdr, uint32_t len,
			 uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return PACKET_INVALID;
	}

	// offset iphdr by ip header length of 40 bytes to shift pointer to ICMP6 header
	struct icmp *icmp_h = (struct icmp *)(&ip_hdr[1]);

	if (icmp_h->icmp_type != ICMP_ECHOREPLY) {
		return PACKET_INVALID;
	}

	if(icmp_h->icmp_seq != validation[2] & 0xFFFF){
		return PACKET_INVALID;
	}

	return PACKET_VALID;
}

static fielddef_t fields[] = {
    {.name = "type", .type = "int", .desc = "icmp message type"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "icmp id number"},
    {.name = "seq", .type = "int", .desc = "icmp sequence number"},
    {.name = "classification",
     .type = "string",
     .desc = "probe module classification"},
    {.name = "success",
     .type = "int",
     .desc = "did probe module classify response as success"}};

probe_module_t module_gue = {
    .name = "gue",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
		sizeof(struct udphdr) + sizeof(struct guehdr) + sizeof(struct ip) + sizeof(struct icmp),
    .pcap_filter = "icmp[0]==0", // and icmp6[0]=!8",
    .pcap_snaplen =
	118, // 14 ethernet header + 40 IPv6 header + 8 ICMPv6 header + 40 inner IPv6 header + 8 inner ICMPv6 header + 8 payload
    .port_args = 1,
    .global_initialize = &gue_global_initialize,
    .thread_initialize = &gue_init_perthread,
    .make_packet = &gue_make_packet,
    .print_packet = &gue_print_packet,
    .process_packet = &gue_process_packet,
    .validate_packet = &gue_validate_packet,
    .close = NULL,
    .fields = fields,
    .numfields = 6};