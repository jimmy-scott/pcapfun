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

#ifdef __linux__
#include <netinet/ether.h>
#endif /* __linux__ */

/* function prototypes */
static void usage(char *program);
static pcap_t *setup_capture(char *device, char *filter);
static int setup_filter(pcap_t *capt, char *device, char *filter);
static pcap_handler get_link_handler(pcap_t *capt);
static void handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

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

static void
handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	uint16_t ether_type;
	struct ether_header *eptr;
	
	/* extract ethernet header */
	eptr = (struct ether_header *)(packet);
	ether_type = ntohs(eptr->ether_type);
	
	printf("[eth] src: %s",
		ether_ntoa((const struct ether_addr *)eptr->ether_shost));
	printf(" dst: %s ",
		ether_ntoa((const struct ether_addr *)eptr->ether_dhost));
	
	/* check packet type */
	if (ether_type == ETHERTYPE_IP) {
		printf("(IP)\n");
	} else if (ether_type == ETHERTYPE_ARP) {
		printf("(ARP)\n");
	} else if (ether_type == ETHERTYPE_REVARP) {
		printf("(RARP)\n");
	} else if (ether_type == ETHERTYPE_IPV6) {
		printf("(IPv6)\n");
	} else {
		printf("(?:%u)\n", ether_type);
	}
	
	/* do something with ether_type */
	
	return;
}

