#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <panel.h>
#include "localtraf.h"
#include "display.h"
#include "sort.h"

static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct host *head = NULL;
static time_t rates_update;
static struct timeval last_update_in;
static struct timeval last_update_out;
static int skip = 0;
static int hosts_num = 0;

static int sort_window(void)
{
    int ret = 0;

    WINDOW *win = newwin(10, 38, LINES / 2 - 5, COLS / 2 - 19);
    PANEL *panel = new_panel(win);

    wbkgdset(win, COLOR_PAIR(1) | A_BOLD);
    werase(win);

    wattron(win, COLOR_PAIR(2));
    box(win, 0 , 0);
    mvwprintw(win, 1, 8, "Select sort criterion:");
    mvwprintw(win, 2, 3, "1");
    mvwprintw(win, 3, 3, "2");
    mvwprintw(win, 4, 3, "3");
    mvwprintw(win, 5, 3, "4");
    mvwprintw(win, 6, 3, "5");
    mvwprintw(win, 7, 3, "6");
    mvwprintw(win, 8, 3, "7");
    wattroff(win, COLOR_PAIR(2));

    mvwprintw(win, 2, 4, " - sort by IP/Hostname");
    mvwprintw(win, 3, 4, " - sort by Incoming Packets");
    mvwprintw(win, 4, 4, " - sort by Outgoing Packets");
    mvwprintw(win, 5, 4, " - sort by Incoming Bytes");
    mvwprintw(win, 6, 4, " - sort by Outgoing Bytes");
    mvwprintw(win, 7, 4, " - sort by Incoming Rates");
    mvwprintw(win, 8, 4, " - sort by Outgoing Rates");

    update_panels();
    doupdate();

    ret = wgetch(win);

    del_panel(panel);
    delwin(win);
    erase();

    return ret;
}

static void print_header(struct options *opts)
{
    if (!(opts->fp = fopen(opts->outfile, "w"))) {
	fprintf(stderr, "File %s could not be openning for writing.\n", opts->outfile);
	exit(EXIT_FAILURE);
    }

    fprintf(opts->fp, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
    fprintf(opts->fp, "<html>\n<head>\n<meta http-equiv=\"refresh\" content=\"5\" url=\"%s\" />\n", opts->outfile);
    fprintf(opts->fp, "<title>Localtraf</title>\n<link href=\"sarg.css\" rel=\"stylesheet\" type=\"text/css\">\n</head>\n<body>\n");
    fprintf(opts->fp, "<table border=\"1\">\n<tr>\n<th>IP</th><th>Hostname</th><th>Incoming Packets</th><th>Outgoing Packets</th>");
    fprintf(opts->fp, "<th>Incoming Bytes</th><th>Outgoing Bytes</th><th>Incoming Rates</th><th>Outgoing Rates</th>\n</tr>\n");
}

static void free_list(void)
{
    struct host *cur, *next;

    pthread_mutex_lock(&list_lock);

    for (cur = head; cur; cur = next) {
	next = cur->next;
	free(cur);
    }

    head = NULL;

    pthread_mutex_unlock(&list_lock);
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

static void iptostr(char *dst, u_int32_t ip)
{
//    sprintf(dst, "%hhu.%hhu.%hhu.%hhu",
//	(ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
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

static void resolve_all_hosts(void)
{
    struct host *cur;

    for (cur = head; cur; cur = cur->next) {
	resolve_host(cur);
    }
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

static void update_counts(u_int32_t ip, const struct pcap_pkthdr *header, int direction, struct options *opts)
{
    struct host *prev, *cur;

    pthread_mutex_lock(&list_lock);

    /* Search host in list. */
    for (cur = head; cur; cur = cur->next) {
	if (cur->ip == ip) {
	    cur->timestamp = header->ts.tv_sec;

	    if (direction == PCAP_D_IN) {
		cur->out_bytes += header->len;
		cur->out_packets++;
	    } else {
		cur->in_bytes += header->len;
		cur->in_packets++;
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

    if (opts->resolve)
	resolve_host(cur);

    if (direction == PCAP_D_IN) {
	cur->out_bytes = header->len;
	cur->out_packets++;
    } else {
	cur->in_bytes = header->len;
	cur->in_packets++;
    }

    if (head == NULL)
	head = cur;
    else
	prev->next = cur;

    hosts_num++;

    sort(&head, hosts_num, opts);

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

    int s1 = 21.22 * (COLS - 80) / 100 + 1;
    int s2 = 12.12 * (COLS - 80) / 100 + 1;
    int s3 = 15.15 * (COLS - 80) / 100 + 1;

    pthread_mutex_lock(&list_lock);

    attron(COLOR_PAIR(2));
    mvprintw(line++, 0, "IP Address           %*s%*sIncoming%*sOutgoing%*sIncoming%*sOutgoing  %*sIncoming  %*sOutgoing",
	s1, " ", s2, " ", s2, " ", s2, " ", s2, " ", s3, " ", s3, " ");
    mvprintw(line++, 0, "                      %*s%*sPackets %*sPackets   %*sBytes   %*sBytes     %*sRates     %*sRates",
	s1, " ", s2, " ", s2, " ", s2, " ", s2, " ", s3, " ", s3, " ");
    attroff(COLOR_PAIR(2));

    for (cur = head, num = 0; cur; cur = cur->next, num++) {
	if ((num >= skip) && (num - skip < LINES - 5)) {
	    packets_short(in_packets, sizeof(in_packets), cur->in_packets);
	    packets_short(out_packets, sizeof(out_packets), cur->out_packets);
	    bytes_short(in_bytes, sizeof(in_bytes), cur->in_bytes);
	    bytes_short(out_bytes, sizeof(out_bytes), cur->out_bytes);

	    mvprintw(line++, 0, "%-*.*s %*s %*s %*s %*s %*uKb/s %*uKb/s\n",
		21 + s1, 21 + s1, (opts->resolve && cur->visible_name[0]) ? cur->visible_name : cur->visible_ip,
		7 + s2, in_packets,
		7 + s2, out_packets,
		7 + s2, in_bytes,
		7 + s2, out_bytes,
		5 + s3, cur->in_rates,
		5 + s3, cur->out_rates);
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
    mvprintw(LINES - 1, 1, "Up/Down/PgUp/PgDn                S       Q");
    mvprintw(line++, 0,"%-*s ", 21 + s1, "Total:");
    attroff(COLOR_PAIR(2));

    packets_short(in_packets, sizeof(in_packets), total_in_packets);
    packets_short(out_packets, sizeof(out_packets), total_out_packets);
    bytes_short(in_bytes, sizeof(in_bytes), total_in_bytes);
    bytes_short(out_bytes, sizeof(out_bytes), total_out_bytes);

    printw("%*s %*s %*s %*s %*uKb/s %*uKb/s\n",
	7 + s2, in_packets,
	7 + s2, out_packets,
	7 + s2, in_bytes,
	7 + s2, out_bytes,
	5 + s3, total_in_rates,
	5 + s3, total_out_rates);

    mvprintw(LINES - 1, 18, "-scroll window");
    mvprintw(LINES - 1, 35, "-sort");
    mvprintw(LINES - 1, 43, "-quit");

    update_panels();
    doupdate();

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
	    cur->visible_ip,
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
	/* Delete hosts which were not updated more than 60 seconds. */
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

static void process_packet_in(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct options *opts = (struct options *) param;
    struct iphdr *ip = (struct iphdr *) (pkt_data + ETH_HLEN);
    time_t passed = header->ts.tv_sec - rates_update;

    update_counts(ip->saddr, header, PCAP_D_IN, opts);

    if (passed >= 5) {
	rates_update = header->ts.tv_sec;
	update_rates(passed, opts);
	delete_inactive(opts);
	erase();
    }

    if (timergrow(header->ts, last_update_in, 0.1)) {
	last_update_in = header->ts;

/*	if (opts->fp) {
	    delete_inactive(opts);
	    update_file(opts);
	} else {
*/	    update_display(opts);
//	}
    }
}

static void process_packet_out(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct options *opts = (struct options *) param;
    struct iphdr *ip = (struct iphdr *) (pkt_data + ETH_HLEN);
    time_t passed = header->ts.tv_sec - rates_update;

    update_counts(ip->daddr, header, PCAP_D_OUT, opts);

    if (passed >= 5) {
	rates_update = header->ts.tv_sec;
	update_rates(passed, opts);
	delete_inactive(opts);
	erase();
    }

    if (timergrow(header->ts, last_update_out, 0.1)) {
	last_update_out = header->ts;

/*	if (opts->fp) {
	    delete_inactive(opts);
	    update_file(opts);
	} else {
*/	    update_display(opts);
//	}
    }
}

static void *pcap_thread_in(void *arg)
{
    struct options *opts = (struct options *) arg;

    pcap_loop(opts->handle_in, -1, process_packet_in, (u_char *) opts);

    return NULL;
}

static void *pcap_thread_out(void *arg)
{
    struct options *opts = (struct options *) arg;

    pcap_loop(opts->handle_out, -1, process_packet_out, (u_char *) opts);

    return NULL;
}

void show_display(struct options *opts)
{
    pthread_t pcap_thr_in;
    pthread_t pcap_thr_out;
    int run = TRUE;
    struct timeval tv;
    int OLD_LINES = LINES;
    int OLD_COLS = COLS;
    PANEL *panel;

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
    /* Create panel. */
    panel = new_panel(stdscr);

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
    pthread_create(&pcap_thr_in, NULL, pcap_thread_in, opts);
    pthread_create(&pcap_thr_out, NULL, pcap_thread_out, opts);

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
	    case KEY_PPAGE:
		if (skip > 0) {
		    skip -= LINES - 5;
		    if (skip < 0)
			skip = 0;
		    erase();
		    update_display(opts);
		}
		break;
	    case KEY_NPAGE:
		if ((LINES - 5) < (hosts_num - skip)) {
		    skip += LINES - 5;
		    erase();
		    update_display(opts);
		}
		break;
	    case 'q':
	    case 'Q':
		run = FALSE;
		break;
	    case 'r':
	    case 'R':
		if (!opts->resolve)
		    resolve_all_hosts();
		opts->resolve = ~opts->resolve;
		erase();
		update_display(opts);
		break;
	    case 's':
	    case 'S':
		do {
		    opts->sort = sort_window();
		    erase();
		    update_display(opts);
		} while (opts->sort < '1' || opts->sort > '7');
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
    pthread_detach(pcap_thr_in);
    pthread_cancel(pcap_thr_in);
    pcap_close(opts->handle_in);

    pthread_detach(pcap_thr_out);
    pthread_cancel(pcap_thr_out);
    pcap_close(opts->handle_out);

    del_panel(panel);
    endwin();
    free_list();
}

void start_daemon(struct options *opts)
{
    struct timeval tv;
    pthread_t pcap_thr_in;
    pthread_t pcap_thr_out;

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);
    rates_update = tv.tv_sec;

    /* Create pcap_loop thread. */
    pthread_create(&pcap_thr_in, NULL, pcap_thread_in, opts);
    pthread_create(&pcap_thr_out, NULL, pcap_thread_out, opts);

    print_header(opts);
    fclose(opts->fp);

    while (!sleep(1));

    /* Cleanup. */
    pthread_detach(pcap_thr_in);
    pthread_cancel(pcap_thr_in);
    pcap_close(opts->handle_in);

    pthread_detach(pcap_thr_out);
    pthread_cancel(pcap_thr_out);
    pcap_close(opts->handle_out);

    free_list();
}
