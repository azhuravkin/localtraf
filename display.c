#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include "localtraf.h"
#include "display.h"
#include "sort.h"

static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct host *head = NULL;
static time_t rates_update;
static struct timeval last_update;
static int skip = 0;
static int hosts_num = 0;
static char *sort_by[7] =
    {"IP Address", "Incoming Packets", "Outgoing Packets", "Incoming Bytes", "Outgoing Bytes", "Incoming Rates", "Outgoing Rates"};

static void print_header(struct options *opts)
{
    if (!(opts->fp = fopen(opts->outfile, "w"))) {
	fprintf(stderr, "File %s could not be openning for writing.\n", opts->outfile);
	exit(EXIT_FAILURE);
    }

    fprintf(opts->fp, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
    fprintf(opts->fp, "<html>\n<head>\n<meta http-equiv=\"refresh\" content=\"5\" url=\"%s\" />\n", opts->outfile);
    fprintf(opts->fp, "<title>Localtraf</title>\n<link href=\"sarg.css\" rel=\"stylesheet\" type=\"text/css\">\n</head>\n<body>\n");
    fprintf(opts->fp, "<table border=\"1\">\n<tr>\n<th>IP/MAC Address</th><th>Hostname</th><th>Incoming Packets</th><th>Outgoing Packets</th>");
    fprintf(opts->fp, "<th>Incoming Bytes</th><th>Outgoing Bytes</th><th>Incoming Rates</th><th>Outgoing Rates</th>\n</tr>\n");
}

static void free_list(void)
{
    struct host *cur, *next;

    for (cur = head; cur; cur = next) {
	next = cur->next;
	free(cur);
    }
}

static void packets_short(char *dst, size_t size, u_int32_t packets)
{
    if (packets > 100000)
	snprintf(dst, size, "%uK", packets / 1000);
    else
	snprintf(dst, size, "%u", packets);
}

static void bytes_short(char *dst, size_t size, u_int32_t bytes)
{
    if (bytes > 102400)
	snprintf(dst, size, "%uK", bytes / 1024);
    else
	snprintf(dst, size, "%u", bytes);
}

static void mactostr(char *dst, unsigned char *mac)
{
    char *hex = "0123456789ABCDEF";
    int i;

    for (i = 0; i < 6; i++) {
	*dst++ = hex[*mac >> 4];
	*dst++ = hex[*mac++ & 0xf];
	*dst++ = ':';
    }

    *--dst = '\0';
}

static void iptostr(char *dst, u_int32_t ip)
{
    struct in_addr addr;

    addr.s_addr = ip;

    sprintf(dst, "%s", inet_ntoa(addr));
}

static void resolve_host(struct host *cur)
{
    struct hostent *he;

    if ((he = gethostbyaddr(&cur->ip, 4, AF_INET)))
	snprintf(cur->visible_name, sizeof(cur->visible_name), "%s", he->h_name);
}

static void update_rates(time_t passed, struct options *opts)
{
    struct host *cur;

    pthread_mutex_lock(&list_lock);

    for (cur = head; cur; cur = cur->next) {
	cur->in_rates = ((cur->in_bytes - cur->in_bytes_prev) * 8 / 1000) / passed;
	cur->out_rates = ((cur->out_bytes - cur->out_bytes_prev) * 8 / 1000) / passed;
	cur->in_bytes_prev = cur->in_bytes;
	cur->out_bytes_prev = cur->out_bytes;
    }

    pthread_mutex_unlock(&list_lock);
}

static void update_counts(u_int32_t ip, unsigned char *mac, const struct pcap_pkthdr *header, int direction, struct options *opts)
{
    struct host *prev, *cur;

    pthread_mutex_lock(&list_lock);

    /* Search host in list. */
    for (cur = head; cur; cur = cur->next) {
	if (cur->ip == ip) {
	    cur->timestamp = header->ts.tv_sec;

	    if (direction == RECEIVE) {
		cur->in_bytes += header->len;
		cur->in_packets++;
	    } else {
		cur->out_bytes += header->len;
		cur->out_packets++;
	    }

	    pthread_mutex_unlock(&list_lock);

	    return;
	}
	prev = cur;
    }

    /* Add new host. */
    cur = malloc(sizeof(struct host));
    memset(cur, 0, sizeof(struct host));
    cur->timestamp = header->ts.tv_sec;
    cur->ip = ip;
    iptostr(cur->visible_ip, ip);
    mactostr(cur->visible_mac, mac);

    if (opts->resolve)
	resolve_host(cur);

    if (direction == RECEIVE) {
	cur->in_bytes = header->len;
	cur->in_packets++;
    } else {
	cur->out_bytes = header->len;
	cur->out_packets++;
    }

    if (head == NULL)
	head = cur;
    else
	prev->next = cur;

    hosts_num++;

    pthread_mutex_unlock(&list_lock);
}

static void update_display(struct options *opts)
{
    struct host *cur;
    int num, line = 0;
    char in_packets[9];
    char out_packets[9];
    char in_bytes[9];
    char out_bytes[9];
    u_int32_t total_in_packets  = 0;
    u_int32_t total_out_packets = 0;
    u_int32_t total_in_bytes    = 0;
    u_int32_t total_out_bytes   = 0;
    u_int32_t total_in_rates    = 0;
    u_int32_t total_out_rates   = 0;

    int space1 = 33.34 * (COLS - 80) / 100 + 1;
    int space2 = 12.12 * (COLS - 80) / 100 + 1;
    int space3 = 15.15 * (COLS - 80) / 100 + 1;

    pthread_mutex_lock(&list_lock);

    attron(COLOR_PAIR(2));
    mvprintw(line++, 0, "IP Address            %*sIncoming%*sOutgoing%*sIncoming%*sOutgoing  %*sIncoming  %*sOutgoing", S1, S2, S2, S2, S3, S3);
    mvprintw(line++, 0, "                       %*sPackets %*sPackets   %*sBytes   %*sBytes     %*sRates     %*sRates", S1, S2, S2, S2, S3, S3);
    attroff(COLOR_PAIR(2));

    for (cur = head, num = 0; cur; cur = cur->next, num++) {
	if ((num >= skip) && (num - skip < LINES - 5)) {
	    packets_short(in_packets, sizeof(in_packets), cur->in_packets);
	    packets_short(out_packets, sizeof(out_packets), cur->out_packets);
	    bytes_short(in_bytes, sizeof(in_bytes), cur->in_bytes);
	    bytes_short(out_bytes, sizeof(out_bytes), cur->out_bytes);

	    mvprintw(line++, 0, "%-22s%*s%8s%*s%8s%*s%8s%*s%8s%*s%6uKb/s%*s%6uKb/s\n",
		(opts->mac) ? cur->visible_mac : (opts->resolve && cur->visible_name[0]) ? cur->visible_name : cur->visible_ip, S1,
		in_packets, S2,
		out_packets, S2,
		in_bytes, S2,
		out_bytes, S3,
		cur->in_rates, S3,
		cur->out_rates);
	}
	total_in_packets  += cur->in_packets;
	total_out_packets += cur->out_packets;
	total_in_bytes    += cur->in_bytes;
	total_out_bytes   += cur->out_bytes;
	total_in_rates    += cur->in_rates;
	total_out_rates   += cur->out_rates;
    }

    attron(COLOR_PAIR(2));
    mvhline(line++, 0, ACS_HLINE, COLS);
    mvprintw(LINES - 1, 1, "q          s/S                              up/down");
    mvprintw(line++, 0,"%-22s%*s", "Total:", S1);
    attroff(COLOR_PAIR(2));

    packets_short(in_packets, sizeof(in_packets), total_in_packets);
    packets_short(out_packets, sizeof(out_packets), total_out_packets);
    bytes_short(in_bytes, sizeof(in_bytes), total_in_bytes);
    bytes_short(out_bytes, sizeof(out_bytes), total_out_bytes);

    printw("%8s%*s%8s%*s%8s%*s%8s%*s%6uKb/s%*s%6uKb/s\n",
	in_packets, S2,
	out_packets, S2,
	in_bytes, S2,
	out_bytes, S3,
	total_in_rates, S3,
	total_out_rates);

    mvprintw(LINES - 1, 2, " - quit");
    mvprintw(LINES - 1, 15, " - sort by %s", sort_by[opts->sort]);
    mvprintw(LINES - 1, 52, " - scroll window");

    refresh();

    pthread_mutex_unlock(&list_lock);
}

static void update_file(struct options *opts)
{
    struct host *cur;
    int num;
    char in_packets[9];
    char out_packets[9];
    char in_bytes[9];
    char out_bytes[9];
    u_int32_t total_in_packets  = 0;
    u_int32_t total_out_packets = 0;
    u_int32_t total_in_bytes    = 0;
    u_int32_t total_out_bytes   = 0;
    u_int32_t total_in_rates    = 0;
    u_int32_t total_out_rates   = 0;

    pthread_mutex_lock(&list_lock);

    print_header(opts);

    for (cur = head, num = 0; cur; cur = cur->next, num++) {
	packets_short(in_packets, sizeof(in_packets), cur->in_packets);
	packets_short(out_packets, sizeof(out_packets), cur->out_packets);
	bytes_short(in_bytes, sizeof(in_bytes), cur->in_bytes);
	bytes_short(out_bytes, sizeof(out_bytes), cur->out_bytes);

	fprintf(opts->fp, "<tr>\n<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%uKb/s</td><td>%uKb/s</td>\n</tr>\n",
	    (opts->mac) ? cur->visible_mac : cur->visible_ip,
	    (cur->visible_name[0]) ? cur->visible_name : "&nbsp;",
	    in_packets,
	    out_packets,
	    in_bytes,
	    out_bytes,
	    cur->in_rates,
	    cur->out_rates);
	total_in_packets  += cur->in_packets;
	total_out_packets += cur->out_packets;
	total_in_bytes    += cur->in_bytes;
	total_out_bytes   += cur->out_bytes;
	total_in_rates    += cur->in_rates;
	total_out_rates   += cur->out_rates;
    }

    fprintf(opts->fp, "<tr>\n<td><b>Total:</b></td>");

    packets_short(in_packets, sizeof(in_packets), total_in_packets);
    packets_short(out_packets, sizeof(out_packets), total_out_packets);
    bytes_short(in_bytes, sizeof(in_bytes), total_in_bytes);
    bytes_short(out_bytes, sizeof(out_bytes), total_out_bytes);

    fprintf(opts->fp,
	"<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%uKb/s</td><td>%uKb/s</td>\n</tr></table>\n</body>\n</html>\n",
	in_packets,
	out_packets,
	in_bytes,
	out_bytes,
	total_in_rates,
	total_out_rates);

    fclose(opts->fp);

    pthread_mutex_unlock(&list_lock);
}

static void delete_inactive(struct options *opts)
{
    struct host *cur, *next;
    struct host *prev = NULL;
    struct timeval tv;

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);

    pthread_mutex_lock(&list_lock);

    for (cur = head; cur; cur = next) {
	next = cur->next;
	/* Delete hosts which were not updated more than purge_time seconds. */
	if (cur->timestamp + 60 < tv.tv_sec) {
	    if (prev)
		prev->next = cur->next;
	    else
		head = cur->next;
	    free(cur);
	    hosts_num--;
	} else
	    prev = cur;
    }

    sort(&head, hosts_num, opts);

    pthread_mutex_unlock(&list_lock);
}

static void process_packet(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct options *opts = (struct options *) param;
    struct ethhdr *eth = (struct ethhdr *) pkt_data;
    struct iphdr *ip = (struct iphdr *) (pkt_data + ETH_HLEN);
    time_t passed = header->ts.tv_sec - rates_update;

    if ((ip->daddr & opts->mask) == opts->net)
	update_counts(ip->daddr, eth->h_dest, header, RECEIVE, opts);

    if ((ip->saddr & opts->mask) == opts->net)
	update_counts(ip->saddr, eth->h_source, header, TRANSMIT, opts);

    if (passed >= 5) {
	rates_update = header->ts.tv_sec;
	update_rates(passed, opts);
	delete_inactive(opts);
	erase();
    }

    if (timergrow(header->ts, last_update, 0.1)) {
	last_update = header->ts;

/*	if (opts->fp) {
	    delete_inactive(opts);
	    update_file(opts);
	} else {
*/	    update_display(opts);
//	}
    }
}

static void *pcap_thread(void *arg)
{
    struct options *opts = (struct options *) arg;

    pcap_loop(opts->handle, -1, process_packet, (u_char *) opts);

    return NULL;
}

void show_display(struct options *opts)
{
    pthread_t pcap_thr;
    int run = TRUE;
    struct timeval tv;
    int OLD_LINES = LINES;
    int OLD_COLS = COLS;

    /* Start ncurses mode. */
    initscr();

    if ((LINES < 24) || (COLS < 80)) {
	endwin();
	fprintf(stderr, "This program requires a screen size "
			"of at least 80 columns by 24 lines\n");
	exit(EXIT_FAILURE);
    }

    /* Turn off the cursor. */
    curs_set(FALSE);
    /* Disable echo. */
    noecho();
    /* Enable keypad. */
    keypad(stdscr,TRUE);

    /* Start color mode. */
    if ((opts->color) && has_colors()) {
	start_color();
	init_pair(1, COLOR_YELLOW, COLOR_BLUE);
	init_pair(2, COLOR_CYAN, COLOR_BLUE);
	bkgd(COLOR_PAIR(1) | A_BOLD);
    }

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);
    rates_update = tv.tv_sec;

    update_display(opts);

    /* Create pcap_loop thread. */
    pthread_create(&pcap_thr, NULL, pcap_thread, opts);

    while (run) {
	switch (getch()) {
	    case ERR:
		break;
	    case KEY_UP:
		if (skip > 0) {
		    skip--;
		    erase();
		    update_display(opts);
		}
		break;
	    case KEY_DOWN:
		if ((LINES - 5) < (hosts_num - skip)) {
		    skip++;
		    erase();
		    update_display(opts);
		}
		break;
	    case 'q':
		run = FALSE;
		break;
	    case 's':
		opts->sort++;
		if (opts->sort > 6)
		    opts->sort = 0;
		pthread_mutex_lock(&list_lock);
		sort(&head, hosts_num, opts);
		pthread_mutex_unlock(&list_lock);
		update_display(opts);
		break;
	    case 'S':
		opts->sort--;
		if (opts->sort < 0)
		    opts->sort = 6;
		pthread_mutex_lock(&list_lock);
		sort(&head, hosts_num, opts);
		pthread_mutex_unlock(&list_lock);
		update_display(opts);
		break;
	    default:
		break;
	}

	/* Update display if screen is resized. */
	if ((LINES != OLD_LINES) || (COLS != OLD_COLS)) {
	    OLD_LINES = LINES;
	    OLD_COLS = COLS;
	    erase();
	    update_display(opts);
	}
    }

    /* Cleanup. */
    pthread_detach(pcap_thr);
    pthread_cancel(pcap_thr);
    pcap_close(opts->handle);
    endwin();
    free_list();
}

void start_daemon(struct options *opts)
{
    struct timeval tv;
    pthread_t pcap_thr;

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);
    rates_update = tv.tv_sec;

    /* Create pcap_loop thread. */
    pthread_create(&pcap_thr, NULL, pcap_thread, opts);

    print_header(opts);
    fclose(opts->fp);

    while (!sleep(1));

    /* Cleanup. */
    pthread_detach(pcap_thr);
    pthread_cancel(pcap_thr);
    pcap_close(opts->handle);
    free_list();
}
