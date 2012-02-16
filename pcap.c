#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include "main.h"
#include "display.h"

void pcap_init(void) {
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *interface;

    /* Find a capture device if not specified on command-line. */
    if (!opts.interface[0]) {
	if ((interface = pcap_lookupdev(errbuf)) == NULL) {
	    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	} else
	    snprintf(opts.interface, sizeof(opts.interface), "%s", interface);
    }

    /* Open capture device. */
    if ((opts.handle_in = pcap_open_live(opts.interface, SNAPLEN, 0, 0, errbuf)) == NULL) {
	fprintf(stderr, "Couldn't open device %s first: %s\n", opts.interface, errbuf);
	exit(EXIT_FAILURE);
    }

    if ((opts.handle_out = pcap_open_live(opts.interface, SNAPLEN, 0, 0, errbuf)) == NULL) {
	fprintf(stderr, "Couldn't open device %s second: %s\n", opts.interface, errbuf);
	exit(EXIT_FAILURE);
    }

    /* Get interface type. */
    switch (pcap_datalink(opts.handle_in)) {
	/* Ethernet, Loopback */
	case DLT_EN10MB:
	    opts.header_len = ETH_HLEN;
	    break;
	/* PPP, GRE */
	case DLT_LINUX_SLL:
	    opts.header_len = SLL_HDR_LEN;
	    break;
	/* OpenVPN, IPIP */
	case DLT_RAW:
	    opts.header_len = 0;
	    break;
	default:
	    fprintf(stderr, "Interface %s have unsupported type\n", opts.interface);
	    exit(EXIT_FAILURE);
    }

    /* Compile the filter expression. */
    if (pcap_compile(opts.handle_in, &fp, opts.expression, 0, PCAP_NETMASK_UNKNOWN) == EOF) {
	fprintf(stderr, "Couldn't compile filter first: %s\n", pcap_geterr(opts.handle_in));
	exit(EXIT_FAILURE);
    }

    if (pcap_compile(opts.handle_out, &fp, opts.expression, 0, PCAP_NETMASK_UNKNOWN) == EOF) {
	fprintf(stderr, "Couldn't compile filter second: %s\n", pcap_geterr(opts.handle_out));
	exit(EXIT_FAILURE);
    }

    /* Apply the compiled filter. */
    if (pcap_setfilter(opts.handle_in, &fp) == EOF) {
	fprintf(stderr, "Couldn't install filter first: %s\n", pcap_geterr(opts.handle_in));
	exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(opts.handle_out, &fp) == EOF) {
	fprintf(stderr, "Couldn't install filter second: %s\n", pcap_geterr(opts.handle_out));
	exit(EXIT_FAILURE);
    }

    /* Set capture direction. */
    if (pcap_setdirection(opts.handle_in, PCAP_D_IN) == EOF) {
	fprintf(stderr, "Couldn't set direction first: %s\n", pcap_geterr(opts.handle_in));
	exit(EXIT_FAILURE);
    }

    if (pcap_setdirection(opts.handle_out, PCAP_D_OUT) == EOF) {
	fprintf(stderr, "Couldn't set direction second: %s\n", pcap_geterr(opts.handle_out));
	exit(EXIT_FAILURE);
    }
}

void pcap_cancel(void) {
    pcap_close(opts.handle_in);
    pcap_close(opts.handle_out);
}
