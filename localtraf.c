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
	"  -m, --mac              show mac address\n"
	"  -n, --no-color         disable color mode\n"
	"  -o, --outfile <string> write output to <string> file\n"
	"  -r, --resolve          resolve hostnames\n"
	"      interface          listen on <interface>\n", name);
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
    opts.mac = FALSE;
    opts.resolve = FALSE;
    opts.outfile = NULL;
    opts.fp = NULL;
    opts.sort = 5;

    struct option longopts[] = {
	{"help",     0, 0, 'h'},
	{"mac",      0, 0, 'm'},
	{"no-color", 0, 0, 'n'},
	{"outfile",  0, 0, 'o'},
	{"resolve",  0, 0, 'r'},
	{NULL,       0, 0, '\0'}
    };

    /* Parse command line options. */
    while ((opt = getopt_long(argc, argv, "hmno:r", longopts, NULL)) != EOF) {
	switch (opt) {
	    case 'm':
		opts.mac = TRUE;
		break;
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

    /* Get network number and mask associated with capture device. */
    if (pcap_lookupnet(opts.dev, &opts.net, &opts.mask, errbuf) == EOF) {
	fprintf(stderr, "Can't get net and netmask: %s\n", errbuf);
	exit(EXIT_FAILURE);
    }

    /* Open capture device. */
    if ((opts.handle = pcap_open_live(opts.dev, ETH_HLEN + ETH_ZLEN, 0, 0, errbuf)) == NULL) {
	fprintf(stderr, "Couldn't open device %s: %s\n", opts.dev, errbuf);
	exit(EXIT_FAILURE);
    }

    /* Make sure we're capturing on an Ethernet device. */
    if (pcap_datalink(opts.handle) != DLT_EN10MB) {
	fprintf(stderr, "%s is not an Ethernet\n", opts.dev);
	exit(EXIT_FAILURE);
    }

    /* Compile the filter expression. */
    if (pcap_compile(opts.handle, &fp, "ip", 0, opts.mask) == EOF) {
	fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(opts.handle));
	exit(EXIT_FAILURE);
    }

    /* Apply the compiled filter. */
    if (pcap_setfilter(opts.handle, &fp) == EOF) {
	fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(opts.handle));
	exit(EXIT_FAILURE);
    }

    /* Start pcap */
    if (opts.outfile)
	start_daemon(&opts);
    else
	show_display(&opts);

    return 0;
}
