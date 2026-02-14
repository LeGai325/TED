#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "../../lib/includes.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

#define ICMP_UNREACH_HEADER_SIZE 8
#define ICMP_MAX_PAYLOAD_LEN 1458
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8
#define UNUSED __attribute__((unused))

static char *icmp_send_msg = NULL;
static int icmp_send_msg_len = 0;
static const size_t icmp_payload_default_len = 98;
static const char *icmp_send_msg_default = "This message is part of a scan conducted for a masters thesis, put the source address in a browser for more info";
#define DEFUALT_PAYLOAD_LEN (30)

const char *ipip_echo_usage_error =
    "unknown UDP probe specification (expected file:/path or text:STRING or hex:01020304)";

probe_module_t module_ipip_echo;

int ipip_echo_global_initialize(struct state_conf *conf)
{
	return EXIT_SUCCESS;
}


int ipip_echo_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
			UNUSED port_h_t dst_port, UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) * 2 + sizeof(struct icmp));
	make_ip_header(ip_header, IPPROTO_IPIP, len);

	struct ip *ip_header2 = (struct ip *)&ip_header[1];
	len =
	     htons(sizeof(struct ip) + sizeof(struct icmp));
	make_ip_header(ip_header2, IPPROTO_ICMP, len);

	struct icmp *icmp_header = (struct icmp *)(&ip_header2[1]);
	make_icmp_header2(icmp_header,ICMP_ECHO);

	return EXIT_SUCCESS;
}

int ipip_echo_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
		     ipaddr_n_t dst_ip, UNUSED uint8_t ttl,
		     uint32_t *validation, int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct ip *ip_header2 = (struct ip *)(&ip_header[1]);
	struct icmp *icmp_header = (struct icmp *)&ip_header2[1];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	ip_header2->ip_src = ((struct in_addr *)arg)[0];; // external_ip
	
	if (ip_header2->ip_src.s_addr == INADDR_ANY)
	{
		ip_header2->ip_src.s_addr = src_ip;
	}

	ip_header2->ip_dst.s_addr = dst_ip;

	uint16_t icmp_idnum = validation[1] & 0xFFFF;
	uint16_t icmp_seqnum = validation[2] & 0xFFFF;
	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_seq = icmp_seqnum;

	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum = icmp_checksum((unsigned short *)icmp_header, ICMP_MINLEN);

	ip_header2->ip_sum = 0;
	ip_header2->ip_sum = zmap_ip_checksum((unsigned short *)ip_header2);
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	// Output the total length of the packet
	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ip) + sizeof(struct icmp);
	return EXIT_SUCCESS;
}

void ipip_echo_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct ip *iph2 = (struct ip *)&iph[1];
	struct icmp *icmp_header = (struct icmp *)(&iph2[1]);

	fprintf(fp,
		"icmp { type: %u | code: %u "
		"| checksum: %#04X | id: %u | seq: %u }\n",
		icmp_header->icmp_type, icmp_header->icmp_code,
		ntohs(icmp_header->icmp_cksum), ntohs(icmp_header->icmp_id),
		ntohs(icmp_header->icmp_seq));
	fprintf_ip_header(fp, iph);
	fprintf_ip_header(fp, iph2);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, PRINT_PACKET_SEP);
}

void ipip_echo_process_packet(const u_char *packet, UNUSED uint32_t len,
			 fieldset_t *fs, UNUSED uint32_t *validation,
			 UNUSED const struct timespec ts)
{
	
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct icmp *icmp_hdr =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	fs_add_uint64(fs, "type", icmp_hdr->icmp_type);
	fs_add_uint64(fs, "code", icmp_hdr->icmp_code);
	fs_add_uint64(fs, "icmp_id", ntohs(icmp_hdr->icmp_id));
	fs_add_uint64(fs, "seq", ntohs(icmp_hdr->icmp_seq));

	uint32_t hdrlen = sizeof(struct ether_header) + 4 * ip_hdr->ip_hl + 4;

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
	case ICMP_TIMXCEED:
		fs_add_string(fs, "classification", (char *)"timxceed", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	default:
		fs_add_string(fs, "classification", (char *)"other", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	}

	int datalen = len - hdrlen;

	if(datalen > 0) {
		const uint8_t *data = (uint8_t *)&packet[hdrlen];
		fs_add_binary(fs, "data", (size_t)datalen, (void *)data, 0);
	} else {
		fs_add_null(fs, "data");
	}
}


static int ipip_echo_validate_id_seq(struct icmp *icmp_h, uint32_t *validation)
{
	if (icmp_h->icmp_id != (validation[1] & 0xFFFF)) {
		return PACKET_INVALID;
	}
	if (icmp_h->icmp_seq != (validation[2] & 0xFFFF)) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

static int ipip_echo_validate_packet(const struct ip *ip_hdr, uint32_t len,
				UNUSED uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return PACKET_INVALID;
	}
	struct icmp *icmp_h = get_icmp_header(ip_hdr, len);
	if (!icmp_h) {
		return PACKET_INVALID;
	}
	if (icmp_h->icmp_type == ICMP_ECHOREPLY) {
		return ipip_echo_validate_id_seq(icmp_h, validation);
	} else {
		// handle unresearch/quench/redirect/timeout
		struct ip *ip_inner;
		size_t ip_inner_len;
		int icmp_inner_valid = icmp_helper_validate(
		    ip_hdr, len, sizeof(struct icmp), &ip_inner, &ip_inner_len);
		if (icmp_inner_valid == PACKET_INVALID) {
			return PACKET_INVALID;
		}
		struct icmp *icmp_inner =
		    get_icmp_header(ip_inner, ip_inner_len);
		if (!icmp_inner) {
			return PACKET_INVALID;
		}
		validate_gen(ip_hdr->ip_dst.s_addr, ip_inner->ip_dst.s_addr,
			     (uint8_t *)validation);
		// validate icmp id and seqnum
		return ipip_echo_validate_id_seq(icmp_inner, validation);
	}
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
	 .desc = "did probe module classify response as success"},
	{.name = "data", .type = "binary", .desc = "ICMP payload"}};

probe_module_t module_ipip_echo = {
    .name = "ipip_echo",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) * 2 +
		     sizeof(struct icmp),
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 1500,
    .port_args = 0,
    .thread_initialize = &ipip_echo_init_perthread,
    .global_initialize = &ipip_echo_global_initialize,
    .make_packet = &ipip_echo_make_packet,
    .print_packet = &ipip_echo_print_packet,
    .validate_packet = &ipip_echo_validate_packet,
    .process_packet = &ipip_echo_process_packet,
    .close = NULL,
    .helptext = "Probe module that sends UDP packets to hosts. Packets can "
		"optionally be templated based on destination host. Specify"
		" packet file with --probe-args=file:/path_to_packet_file "
		"and templates with template:/path_to_template_file.",
    .fields = fields,
    .numfields = 7};
