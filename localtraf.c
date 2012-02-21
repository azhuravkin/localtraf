#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include "localtraf.h"
#include "display.h"

static void usage(const char *name)
{
    fprintf(stderr,
	"Usage: %s [Options] [interface]\n"
	"Options:\n"
	"  -b, --kbytes           show rate in kilobytes per second\n"
	"  -f, --filter <string>  filter expression; see tcpdump(1) for syntax\n"
	"  -h, --help             show this (help) message\n"
	"  -m, --mac              show mac address\n"
	"  -n, --no-color         disable color mode\n"
	"  -r, --resolve          resolve hostnames\n"
	"  -P, --purge <num>      set the expired data purge-period to <num> seconds [60]\n"
	"  -R, --refresh <num>    set the refresh-period to <num> seconds [1]\n"
	"      interface          listen on <interface>\n", name);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    struct options opts;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[128] = "ip";
    int opt;

    if (getuid()) {
	fprintf(stderr, "This program can be run only by root.\n");
	exit(EXIT_FAILURE);
    }

    setlocale(LC_ALL, "");

    opts.refresh_time = 1;
    opts.purge_time = 60;
    opts.color = TRUE;
    opts.mac = FALSE;
    opts.kbytes = FALSE;
    opts.resolve = FALSE;

    struct option longopts[] = {
	{"kbytes",   0, 0, 'b'},
	{"filter",   1, 0, 'f'},
	{"help",     0, 0, 'h'},
	{"mac",      0, 0, 'm'},
	{"no-color", 0, 0, 'n'},
	{"resolve",  0, 0, 'r'},
	{"purge",    1, 0, 'P'},
	{"refresh",  1, 0, 'R'},
	{NULL,       0, 0, '\0'}
    };

    /* Parse command line options. */
    while ((opt = getopt_long(argc, argv, "kf:mnrP:R:", longopts, NULL)) != EOF) {
	switch (opt) {
	    case 'k':
		opts.kbytes = TRUE;
		break;
	    case 'f':
		snprintf(filter, sizeof(filter), "ip and %s", optarg);
		break;
	    case 'm':
		opts.mac = TRUE;
		break;
	    case 'n':
		opts.color = FALSE;
		break;
	    case 'r':
		opts.resolve = TRUE;
		break;
	    case 'P':
		opts.purge_time = atoi(optarg);
		break;
	    case 'R':
		opts.refresh_time = atoi(optarg);
		break;
	    default:
		usage(argv[0]);
		break;
	}
    }

/*    if (opts.refresh_time < 1) {
	fprintf(stderr, "Refresh Time (%d sec) must be one or more seconds.\n",
		opts.refresh_time);
	exit(EXIT_FAILURE);
    }
*/
    if (opts.purge_time < opts.refresh_time) {
	fprintf(stderr, "Refresh Time (%d second) must be less than Purge Time (%d second).\n",
		opts.refresh_time, opts.purge_time);
	exit(EXIT_FAILURE);
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
    if (pcap_compile(opts.handle, &fp, filter, 0, opts.mask) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(opts.handle));
	exit(EXIT_FAILURE);
    }

    /* Apply the compiled filter. */
    if (pcap_setfilter(opts.handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(opts.handle));
	exit(EXIT_FAILURE);
    }

    /* Show display. */
    display(&opts);

    return 0;
}
