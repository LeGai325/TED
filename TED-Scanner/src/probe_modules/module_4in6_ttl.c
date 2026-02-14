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

probe_module_t module_4in6_ttl;

int fourIn6_ttl_global_initialize(struct state_conf *conf)
{
	if(!zconf.spoofing_address_v4){
		log_error("4in6_ttl", "Spoofing address was not given. Add --spoofing-address-v4");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int fourIn6_ttl_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				      __attribute__((unused)) port_h_t dst_port,
				      __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);

	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	uint16_t payload_len = sizeof(struct ip) + sizeof(struct icmp);
	make_ip6_header(ip6_header, IPPROTO_IPIP, payload_len);

	struct ip *ip_header = (struct ip *)(&ip6_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	payload_len = htons(sizeof(struct ip) + sizeof(struct icmp));
	make_ip_header(ip_header, IPPROTO_ICMP, payload_len);

	struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);
	make_icmp_header2(icmp_header, ICMP_ECHOREPLY);

	return EXIT_SUCCESS;
}

static int fourIn6_ttl_make_packet(void *buf, size_t *buf_len,
				   ipaddr_n_t src_ip, UNUSED ipaddr_n_t dst_ip,
				   uint8_t ttl, uint32_t *validation,
				   int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	struct ip *ip_header = (struct ip *)(&ip6_header[1]);
	struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);

	uint32_t index = (uint32_t)zsend.current_host;
	uint16_t icmp_idnum = (uint16_t)(index >> 16);
	uint16_t icmp_seqnum = (uint16_t)(index & 0xFFFF);

	// Include validation in ICMPv6 payload data

	struct in6_addr *addr6_1 = (struct in6_addr *)arg;
    struct in6_addr *addr6_2 = (struct in6_addr *)(&addr6_1[1]);
    struct in_addr *addr4_1 = (struct in_addr *)(&addr6_2[1]);
    struct in_addr *addr4_2 = (struct in_addr *)(&addr4_1[1]);

	ip6_header->ip6_src = *addr6_1;
	ip6_header->ip6_dst = *addr6_2;

	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = MAXTTL;

	ip_header->ip_src = *addr4_2; // External address
	ip_header->ip_dst = *addr4_1; //Random spoofed address

	if (ip_header->ip_src.s_addr == INADDR_ANY)
	{
		ip_header->ip_src.s_addr = src_ip;
	}


	ip_header->ip_ttl = 1; //ttl expired

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_seq = icmp_seqnum;

	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum =
	    icmp_checksum((unsigned short *)icmp_header, sizeof(struct icmp));

	*buf_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
		   sizeof(struct ip) + sizeof(struct icmp);

	return EXIT_SUCCESS;
}

static void fourIn6_ttl_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip6_hdr *iph = (struct ip6_hdr *)&ethh[1];
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&iph[1]);

	fprintf(fp,
		"icmp { type: %u | code: %u "
		"| checksum: %#04X | id: %u | seq: %u }\n",
		icmp6_header->icmp6_type, icmp6_header->icmp6_code,
		ntohs(icmp6_header->icmp6_cksum), ntohs(icmp6_header->icmp6_id),
		ntohs(icmp6_header->icmp6_seq));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int fourIn6_ttl_validate_packet(const struct ip *ip_hdr, uint32_t len,
				       uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return PACKET_INVALID;
	}

	// offset iphdr by ip header length of 40 bytes to shift pointer to ICMP6 header
	struct icmp *icmp_hdr = (struct icmp *)(&ip_hdr[1]);

	if (icmp_hdr->icmp_type != ICMP_TIME_EXCEEDED) {
		return PACKET_INVALID;
	}
	
	if (icmp_hdr->icmp_ip.ip_p != IPPROTO_ICMP) {
		return PACKET_INVALID;
	}

	return PACKET_VALID;
}

static void fourIn6_ttl_process_packet(const u_char *packet,
				       __attribute__((unused)) uint32_t len,
				       fieldset_t *fs,
				       __attribute__((unused))
				       uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct icmp *icmp_hdr = (struct icmp *)(&ip_hdr[1]);
	fs_add_uint64(fs, "type", icmp_hdr->icmp_type);
	struct icmp *inner_icmp = (struct icmp *)&packet[sizeof(struct ether_header) + sizeof(struct ip) + ICMP_MINLEN + sizeof(struct ip)];
	uint16_t id = inner_icmp->icmp_id;
	uint16_t seq = inner_icmp->icmp_seq;
	fs_add_uint64(fs, "actual_src_index", ((int)(id << 16) | seq));
	fs_add_string(fs, "tunnel_addr", make_ip_str2(&(ip_hdr->ip_src)),1);
	fs_add_uint64(fs, "code", icmp_hdr->icmp_code);
	fs_add_uint64(fs, "icmp_id", ntohs(icmp_hdr->icmp_id));
	fs_add_uint64(fs, "seq", ntohs(icmp_hdr->icmp_seq));

	switch (icmp_hdr->icmp_type) {
	case ICMP_ECHOREPLY:
		fs_add_string(fs, "classification", (char *)"echoreply", 0);
		fs_add_uint64(fs, "success", 0);
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
		fs_add_uint64(fs, "success", 1);
		break;
	default:
		fs_add_string(fs, "classification", (char *)"other", 0);
		fs_add_uint64(fs, "success", 0);
		break;
	}
}
static fielddef_t fields[] = {
    {.name = "type", .type = "int", .desc = "icmp message type"},
    {.name = "actual_src_index",
     .type = "int",
     .desc = "the actual source address embedded in the reply"},
    {.name = "tunnel_addr",
     .type = "string",
     .desc = "The address of the ipv4 tunnell"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "icmp id number"},
    {.name = "seq", .type = "int", .desc = "icmp sequence number"},
    {.name = "classification",
     .type = "string",
     .desc = "probe module classification"},
    {.name = "success",
     .type = "int",
     .desc = "did probe module classify response as success"}};

probe_module_t module_4in6_ttl = {
    .name = "4in6_ttl",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
			 sizeof(struct ip) + sizeof(struct icmp),
    .pcap_filter = "icmp[0] == 11",
    .pcap_snaplen =
	118, // 14 ethernet header + 40 IPv6 header + 8 ICMPv6 header + 40 inner IPv6 header + 8 inner ICMPv6 header + 8 payload
    .port_args = 0,
    .global_initialize = &fourIn6_ttl_global_initialize,
    .thread_initialize = &fourIn6_ttl_init_perthread,
    .make_packet = &fourIn6_ttl_make_packet,
    .print_packet = &fourIn6_ttl_print_packet,
    .process_packet = &fourIn6_ttl_process_packet,
    .validate_packet = &fourIn6_ttl_validate_packet,
    .close = NULL,
    .fields = fields,
    .numfields = 8};