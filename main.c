#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <paths.h>
#include <fcntl.h>
#include "main.h"
#include "display.h"

struct options opts;

static void usage(const char *name) {
    fprintf(stderr,
	"Usage: %s [Options] [Expression]\n"
	"Options:\n"
	"  -c, --no-color         disable color mode\n"
	"  -h, --help             show this (help) message\n"
	"  -i, --interface <str>  set \"internal\" interface\n"
	"  -n, --no-resolve       don't resolve ip addresses\n"
	"  -p, --port <num>       listen on <num> port\n"
	"  -r, --resolve          resolve hostnames\n"
	"Expression:              filter expression; see tcpdump(1) for syntax\n", name);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    int iostream;
    int opt;

    if (getuid()) {
	fprintf(stderr, "This program can be run only by root.\n");
	exit(EXIT_FAILURE);
    }

    setlocale(LC_ALL, "");

    memset(opts.interface, '\0', sizeof(opts.interface));
    sprintf(opts.expression, "ip ");
    opts.color = TRUE;
    opts.resolve = TRUE;
    opts.port = 0;

    struct option longopts[] = {
	{"no-color",   0, 0, 'c'},
	{"help",       0, 0, 'h'},
	{"interface",  1, 0, 'i'},
	{"no-resolve", 0, 0, 'n'},
	{"port",       1, 0, 'p'},
	{NULL,         0, 0, '\0'}
    };

    /* Parse command line options. */
    while ((opt = getopt_long(argc, argv, "chi:np:", longopts, NULL)) != EOF) {
	switch (opt) {
	    case 'c':
		opts.color = FALSE;
		break;
	    case 'i':
		snprintf(opts.interface, sizeof(opts.interface), "%s", optarg);
		break;
	    case 'n':
		opts.resolve = FALSE;
		break;
	    case 'p':
		opts.port = atoi(optarg);
		break;
	    default:
		usage(argv[0]);
		break;
	}
    }

    /* Save filter expression */
    if (optind < argc) {
	for (strcat(opts.expression, "and "); optind < argc; optind++) {
	    strncat(opts.expression, argv[optind], sizeof(opts.expression));
	    strncat(opts.expression, " ", sizeof(opts.expression));
	}
    }

    if (opts.port) {
#if 1
	/* Goto background. */
	if (fork())
	    exit(EXIT_SUCCESS);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	iostream = open(_PATH_DEVNULL, O_RDWR);
	dup(iostream);
	dup(iostream);
#endif
	start_daemon();
    } else
	show_display();

    return 0;
}
