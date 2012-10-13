#include <std/XXXXX.h>

#ifdef __linux__
#include <lnx/XXXXX.h>
#endif /* __linux__ */

/* define the header size */
#define XXXXX_SIZE sizeof(struct XXXXX)

/* make a function prototype for protocol handler */
static void handle_XXXXX(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

/*
 * Handle XXXXX protocol.
 */

static void
handle_XXXXX(u_char *args, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	struct XXXXX_header *XXXXX;
	struct stackinfo_t *stackinfo;
	pcap_handler handle_next = NULL;
	
	/* extract stackinfo or get new one */
	if (args)
		stackinfo = (struct stackinfo_t*)(args);
	else
		stackinfo = stackinfo_new();	
	
	/* check if header was captured completely */
	if (pkthdr->caplen - stackinfo->offset < XXXXX_SIZE) {
		printf("[XXXXX] header missing or truncated\n");
		return;
	}
	
	/* extract XXXXX header */
	XXXXX = (struct XXXXX *)(packet + stackinfo->offset);
	
	/* ************************************************ */
	/* ***** extract stuff, check stuff, do stuff ***** */
	/* ************************************************ */
	
	/* next layer to handle */
	handle_next = handle_YYYYY;
	
	/* point to next layer */
	stackinfo->offset += XXXXX_SIZE;
	
	/* handle the next layer */
	if (handle_next)
		handle_next((u_char *)stackinfo, pkthdr, packet);
	
	return;
}

