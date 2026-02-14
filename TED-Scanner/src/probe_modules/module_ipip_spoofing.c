/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP echo request (ping) scans

// Needed for asprintf
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

#define ICMP_SMALLEST_SIZE 5
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

probe_module_t module_ipip_spoofing;

int ipip_spoofing_global_initialize(struct state_conf *conf)
{
	if(!zconf.spoofing_address_v4){
		log_error("ipip_spoofing", "Spoofing IPv4 address was not given. Add --spoofing-address-v4");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int ipip_spoofing_init_perthread(void *buf, macaddr_t *src,
					macaddr_t *gw, UNUSED port_h_t dst_port,
					UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	uint16_t payload_len = htons(sizeof(struct ip) + sizeof(struct ip) +
				     sizeof(struct icmp) + INET_ADDRSTRLEN);
	make_ip_header(ip_header, IPPROTO_IPIP, payload_len);

	struct ip *ip_header2 = (struct ip *)(&ip_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	payload_len =
	    htons(sizeof(struct ip) + sizeof(struct icmp) + INET_ADDRSTRLEN);
	make_ip_header(ip_header2, IPPROTO_ICMP, payload_len);

	struct icmp *icmp_header = (struct icmp *)(&ip_header2[1]);
	make_icmp_header2(icmp_header, ICMP_ECHOREPLY);

	return EXIT_SUCCESS;
}

static int ipip_spoofing_make_packet(void *buf, size_t *buf_len,
				     ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				     uint8_t ttl, uint32_t *validation,
				     UNUSED int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct ip *ip_header2 = (struct ip *)(&ip_header[1]);
	struct icmp *icmp_header = (struct icmp *)(&ip_header2[1]);
	char *payload = (char *)(&icmp_header[1]);

	uint16_t icmp_idnum = validation[1] & 0xFFFF;
	uint16_t icmp_seqnum = validation[2] & 0xFFFF;

	inet_ntop(AF_INET, &(dst_ip), payload, INET_ADDRSTRLEN);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = MAXTTL;

	ip_header2->ip_src = ((struct in_addr *)arg)[0]; //spoofed address

	ip_header2->ip_dst = ((struct in_addr *)arg)[1]; // external_ip
	if (ip_header2->ip_dst.s_addr == INADDR_ANY)
	{
		ip_header2->ip_dst.s_addr = src_ip;
	}
	ip_header2->ip_ttl = MAXTTL;

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	ip_header2->ip_sum = 0;
	ip_header2->ip_sum = zmap_ip_checksum((unsigned short *)ip_header2);

	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_seq = icmp_seqnum;

	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum =
	    icmp_checksum((unsigned short *)icmp_header,
			  sizeof(struct icmp) + strlen(payload));

	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) +
		   sizeof(struct ip) + sizeof(struct icmp) + INET_ADDRSTRLEN;

	return EXIT_SUCCESS;
}

static void ipip_spoofing_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct ip *iph2 = (struct ip *)&iph[1];
	struct icmp *icmp = (struct icmp *)(&iph2[1]);
	fprintf_ip_header(fp, iph2);
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int ipip_spoofing_validate_packet(const struct ip *ip_hdr, uint32_t len,
					 __attribute__((unused))
					 uint32_t *src_ip,
					 uint32_t *validation)
{
	char address[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip_hdr->ip_src.s_addr), address, INET_ADDRSTRLEN);

	if (strcmp(address,zconf.spoofing_address_v4) != 0)
	{
		return PACKET_INVALID;
	}

	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return PACKET_INVALID;
	}

	struct icmp *icmp_h = (struct icmp *)(&ip_hdr[1]);

	if (icmp_h->icmp_type != ICMP_ECHOREPLY) {
		return PACKET_INVALID;
	}

	return PACKET_VALID;
}

static void ipip_spoofing_process_packet(const u_char *packet,
					 __attribute__((unused)) uint32_t len,
					 fieldset_t *fs,
					 __attribute__((unused))
					 uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct icmp *icmp_hdr = (struct icmp *)(&ip_hdr[1]);
	char *payload =
	    (char *)&packet[sizeof(struct ether_header) + sizeof(struct ip) +
			    sizeof(struct icmp)];
	fs_add_uint64(fs, "type", icmp_hdr->icmp_type);
	fs_add_string(fs, "actual_src", payload, 0);
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

static fielddef_t fields[] = {
    {.name = "type", .type = "int", .desc = "icmp message type"},
    {.name = "actual_src",
     .type = "string",
     .desc = "the actual source address embedded in the reply"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "icmp id number"},
    {.name = "seq", .type = "int", .desc = "icmp sequence number"},
    {.name = "classification",
     .type = "string",
     .desc = "probe module classification"},
    {.name = "success",
     .type = "int",
     .desc = "did probe module classify response as success"}};

probe_module_t module_ipip_spoofing = {
    .name = "ipip_spoofing",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
			 sizeof(struct ip) + sizeof(struct icmp) + INET_ADDRSTRLEN,
    .pcap_filter = "icmp[0]==0", // and icmp6[0]=!8",
    .pcap_snaplen =
	118, // 14 ethernet header + 40 IPv6 header + 8 ICMPv6 header + 40 inner IPv6 header + 8 inner ICMPv6 header + 8 payload
    .port_args = 0,
    .global_initialize = &ipip_spoofing_global_initialize,
    .thread_initialize = &ipip_spoofing_init_perthread,
    .make_packet = &ipip_spoofing_make_packet,
    .print_packet = &ipip_spoofing_print_packet,
    .process_packet = &ipip_spoofing_process_packet,
    .validate_packet = &ipip_spoofing_validate_packet,
    .close = NULL,
    .fields = fields,
    .numfields = 7};