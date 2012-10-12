/*
 * Copyright (C) 2012 Jimmy Scott #jimmy#inet-solutions#be#. Belgium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. The names of the authors may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif /* __linux__ */

#define ETHER_SIZE sizeof(struct ether_header)
#define IPV4_SIZE sizeof(struct ip)

typedef struct stackinfo_t {
	bpf_u_int32 offset;
} stackinfo_t;

/* function prototypes */
static void usage(char *program);
static struct stackinfo_t *stackinfo_new(void);
static pcap_t *setup_capture(char *device, char *filter);
static int setup_filter(pcap_t *capt, char *device, char *filter);
static pcap_handler get_link_handler(pcap_t *capt);
static void handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static void handle_ipv4(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int
main(int argc, char **argv)
{
	pcap_t *capt;
	pcap_handler pkt_handler;
	
	/* check usage */
	if (argc != 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	/* setup capturing using device and filter */
	capt = setup_capture(argv[1], argv[2]);
	if (!capt)
		return EXIT_FAILURE;
	
	/* get packet handler based on link type */
	pkt_handler = get_link_handler(capt);
	if (!pkt_handler)
		return EXIT_FAILURE;
	
	/* capture and process 10 packets */
	pcap_loop(capt, 10, pkt_handler, NULL);
	
	return EXIT_SUCCESS;
}

static void
usage(char *program)
{
	fprintf(stderr, "usage: %s <interface> <filter>\n", program);
}

/*
 * Re-initialize stackinfo to default values.
 *
 * The stackinfo structure is used to pass info down the protocol stack:
 *
 *  - The stackinfo.offset is the offset inside the captured packet
 *    where the header (or data) of the current layer starts. Each layer
 *    handler must update this offset to point to the next layer before
 *    calling the handler for the next layer.
 *
 * Returns a pointer to the static stackinfo buffer.
 */

static struct stackinfo_t *
stackinfo_new(void)
{
	static struct stackinfo_t stackinfo;
	
	stackinfo.offset = 0;
	
	return &stackinfo;
}

/*
 * Open capture device and setup capture filter.
 *
 * Returns a packet capture handle (pcap_t).
 */

static pcap_t *
setup_capture(char *device, char *filter)
{
	pcap_t *capt;
	char errbuf[PCAP_ERRBUF_SIZE] = "\0";
	
	/* open device to snoop; parameters:
	 * snaplen = BUFSIZ, promisc = 1, timeout = 100ms */
	capt = pcap_open_live(device, BUFSIZ, 1, 100, errbuf);
	if (capt == NULL) {
		fprintf(stderr, "failed to open %s: %s\n", device, errbuf);
		return NULL;
	}
	
	/* set filter on capture device */
	if (setup_filter(capt, device, filter) == -1) {
		pcap_close(capt);
		return NULL;
	}
	
	return capt;
}

/*
 * Setup a capture filter on a device.
 *
 * Returns 0 if OK, -1 on error.
 */

static int
setup_filter(pcap_t *capt, char *device, char *filter)
{
	bpf_u_int32 network;
	bpf_u_int32 netmask;
	struct bpf_program bpfp;
	char errbuf[PCAP_ERRBUF_SIZE] = "\0";
	
	/* FIXME: does not work without a network */
	
	/* get network and netmask of device */
	if (pcap_lookupnet(device, &network, &netmask, errbuf) == -1) {
		fprintf(stderr, "failed to lookup %s: %s\n", device, errbuf);
		return -1;
	}
	
	/* compile the filter expression */
	if (pcap_compile(capt, &bpfp, filter, 0, network) == -1) {
		fprintf(stderr, "failed to compile filter: %s\n", filter);
		return -1;
	}
	
	/* set the compiled filter */
	if (pcap_setfilter(capt, &bpfp) == -1) {
		fprintf(stderr, "failed to set filter: %s\n", filter);
		return -1;
	}
	
	return 0;
}

/*
 * Determine handler function for first protocol layer.
 *
 * This function checks the link type, and returns a pcap_handler
 * function that is able to handle the first protocol of a packet.
 *
 * Returns a pcap_handler or NULL if the protocol is not yet supported.
 */

static pcap_handler
get_link_handler(pcap_t *capt)
{
	int link_type;
	
	/* get link layer type */
	link_type = pcap_datalink(capt);
	
	/* determine link layer protocol */
	if (link_type == DLT_EN10MB) {
		printf("Link type: Ethernet\n");
		return handle_ethernet;
	} else {
		printf("Link type %i not supported\n", link_type);
		return NULL;
	}
	
	/* never reached */
	return NULL;
}

/* ****************************************************************** */
/* *********************** Protocol handlers ************************ */
/* ****************************************************************** */

/*
 * Handle "10Mb/s" ethernet protocol.
 */

static void
handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	uint16_t ether_type;
	struct ether_header *eptr;
	struct stackinfo_t *stackinfo;
	pcap_handler handle_next = NULL;
	
	/* extract stackinfo or get new one */
	if (args)
		stackinfo = (struct stackinfo_t*)(args);
	else
		stackinfo = stackinfo_new();
	
	/* check if header was captured completely */
	if (pkthdr->caplen - stackinfo->offset < ETHER_SIZE) {
		printf("[eth] header missing or truncated\n");
		return;
	}
	
	/* extract ethernet header */
	eptr = (struct ether_header *)(packet + stackinfo->offset);
	ether_type = ntohs(eptr->ether_type);
	
	printf("[eth] src: %s",
		ether_ntoa((const struct ether_addr *)eptr->ether_shost));
	printf(" dst: %s ",
		ether_ntoa((const struct ether_addr *)eptr->ether_dhost));
	
	/* check packet type */
	if (ether_type == ETHERTYPE_IP) {
		printf("(IP)\n");
		handle_next = handle_ipv4;
	} else if (ether_type == ETHERTYPE_ARP) {
		printf("(ARP)\n");
	} else if (ether_type == ETHERTYPE_REVARP) {
		printf("(RARP)\n");
	} else if (ether_type == ETHERTYPE_IPV6) {
		printf("(IPv6)\n");
	} else {
		printf("(?:%u)\n", ether_type);
	}
	
	/* point to next layer */
	stackinfo->offset += ETHER_SIZE;
	
	/* handle the next layer */
	if (handle_next)
		handle_next((u_char *)stackinfo, pkthdr, packet);
	
	return;
}

/*
 * Handle IPv4 protocol.
 */

static void
handle_ipv4(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	struct ip *ip;
	struct stackinfo_t *stackinfo;
	uint16_t ip_len, ip_off, offset;
	
	/* extract stackinfo or get new one */
	if (args)
		stackinfo = (struct stackinfo_t*)(args);
	else
		stackinfo = stackinfo_new();	
	
	/* check if header was captured completely */
	if (pkthdr->caplen - stackinfo->offset < IPV4_SIZE) {
		printf("[ipv4] header missing or truncated\n");
		return;
	}
	
	/* extract ip header */
	ip = (struct ip *)(packet + stackinfo->offset);
	
	/* extract ip fields to host byte order */
	ip_len = ntohs(ip->ip_len);	/* ip packet length   */
	ip_off = ntohs(ip->ip_off);	/* ip fragment offset */
	
	/* verify ip version */
	if (ip->ip_v != 4) {
		printf("[ipv4] invalid version: %d\n", ip->ip_v);
		return;
	}
	
	/* verify header length */
	if (ip->ip_hl < 5) {
		printf("[ipv4] invalid header length: %d\n", ip->ip_hl);
		return;
	}
	
	/* verify packet length (on the wire) */
	if (pkthdr->len - stackinfo->offset < ip_len) {
		printf("[ipv4] truncated: %u bytes missing\n",
			ip_len - (pkthdr->len - stackinfo->offset));
		/* just a warning, don't return */
	}
	
	/* calculate offset */
	if ((offset = ip_off & IP_OFFMASK) != 0)
		offset <<= 3;
	
	/* determine if first fragment or not */
	if (offset) {
		/* is not the first fragment */
		printf("[ipv4-frag] ");
	} else {
		/* is the first/only fragment */
		printf("[ipv4] ");
	}
	
	/* print remaining info */
	printf("src: %s ", inet_ntoa(ip->ip_src));
	printf("dst: %s ", inet_ntoa(ip->ip_dst));
	printf("len: %u off: %u\n", ip_len, offset);
	
	/* point to next layer */
	stackinfo->offset += IPV4_SIZE;
	
	/* handle the next layer */
	
	return;
}
	
