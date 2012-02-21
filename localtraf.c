#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include "localtraf.h"
#include "display.h"

static void usage(const char *name)
{
    fprintf(stderr,
	"Usage: %s [Options] [interface]\n"
	"Options:\n"
	"  -h, --help             show this (help) message\n"
	"  -n, --no-color         disable color mode\n"
	"  -o, --outfile <string> write output to <string> file\n"
	"  -r, --resolve          resolve hostnames\n"
	"      <interface>        \"internal\" interface\n", name);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    struct options opts;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int opt;

    if (getuid()) {
	fprintf(stderr, "This program can be run only by root.\n");
	exit(EXIT_FAILURE);
    }

    setlocale(LC_ALL, "");

    opts.color = TRUE;
    opts.resolve = FALSE;
    opts.outfile = NULL;
    opts.fp = NULL;
    opts.sort = '6';

    struct option longopts[] = {
	{"help",     0, 0, 'h'},
	{"no-color", 0, 0, 'n'},
	{"outfile",  0, 0, 'o'},
	{"resolve",  0, 0, 'r'},
	{NULL,       0, 0, '\0'}
    };

    /* Parse command line options. */
    while ((opt = getopt_long(argc, argv, "hno:r", longopts, NULL)) != EOF) {
	switch (opt) {
	    case 'n':
		opts.color = FALSE;
		break;
	    case 'o':
		opts.outfile = strdup(optarg);
		break;
	    case 'r':
		opts.resolve = TRUE;
		break;
	    default:
		usage(argv[0]);
		break;
	}
    }

    if (optind < argc) {
	opts.dev = argv[optind];
    } else {
	/* Find a capture device if not specified on command-line. */
	if ((opts.dev = pcap_lookupdev(errbuf)) == NULL) {
	    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}
    }

    /* Open capture device. */
    if ((opts.handle_in = pcap_open_live(opts.dev, ETH_HLEN + ETH_ZLEN, 0, 0, errbuf)) == NULL) {
	fprintf(stderr, "Couldn't open device %s first: %s\n", opts.dev, errbuf);
	exit(EXIT_FAILURE);
    }

    if ((opts.handle_out = pcap_open_live(opts.dev, ETH_HLEN + ETH_ZLEN, 0, 0, errbuf)) == NULL) {
	fprintf(stderr, "Couldn't open device %s second: %s\n", opts.dev, errbuf);
	exit(EXIT_FAILURE);
    }

    /* Make sure we're capturing on an Ethernet device. */
    if (pcap_datalink(opts.handle_in) != DLT_EN10MB) {
	fprintf(stderr, "%s is not an Ethernet\n", opts.dev);
	exit(EXIT_FAILURE);
    }

    /* Compile the filter expression. */
    if (pcap_compile(opts.handle_in, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == EOF) {
	fprintf(stderr, "Couldn't compile filter first: %s\n", pcap_geterr(opts.handle_in));
	exit(EXIT_FAILURE);
    }

    if (pcap_compile(opts.handle_out, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == EOF) {
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

    /* Start pcap */
    if (opts.outfile)
	start_daemon(&opts);
    else
	show_display(&opts);

    return 0;
}
