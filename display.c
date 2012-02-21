#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include "localtraf.h"
#include "display.h"
#include "sort.h"

static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct host *head = NULL;
static time_t rates_update;
static time_t display_update;
static int skip = 0;
static int hosts_num = 0;

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
	snprintf(cur->visible_ip, sizeof(cur->visible_ip), "%s", he->h_name);
}

static void resolve_all_hosts(u_int8_t resolve)
{
    struct host *cur;

    for (cur = head; cur; cur = cur->next) {
	if (resolve)
	    iptostr(cur->visible_ip, cur->ip);
	else
	    resolve_host(cur);
    }
}

static void update_rates(time_t passed, u_int8_t kbytes)
{
    struct host *cur;

    pthread_mutex_lock(&list_lock);

    for (cur = head; cur; cur = cur->next) {
	if (kbytes) {
	    cur->in_rates =
		((cur->in_bytes - cur->in_bytes_prev) / 1024) / passed;
	    cur->out_rates =
		((cur->out_bytes - cur->out_bytes_prev) / 1024) / passed;
	} else {
	    cur->in_rates =
		((cur->in_bytes - cur->in_bytes_prev) * 8 / 1000) / passed;
	    cur->out_rates =
		((cur->out_bytes - cur->out_bytes_prev) * 8 / 1000) / passed;
	}
	cur->in_bytes_prev = cur->in_bytes;
	cur->out_bytes_prev = cur->out_bytes;
    }

    /* Sort by rates in reverse order. */
    sort(&head, hosts_num);

    pthread_mutex_unlock(&list_lock);
}

static void update_counts(u_int32_t ip, unsigned char *mac, const struct pcap_pkthdr *header, int direction, u_int8_t resolve)
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

    if (resolve)
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

    pthread_mutex_lock(&list_lock);

    attron(COLOR_PAIR(2));
    mvprintw(line++, 0, "IP/MAC Address         Incoming Outgoing Incoming Outgoing   Incoming   Outgoing");
    mvprintw(line++, 0, "                        Packets  Packets    Bytes    Bytes      Rates      Rates");
    mvprintw(LINES - 1, 0, "Q-Quit  D-Delete inactive  B-KB/Kb  M-MAC/IP  R-Resolve  Up/Dn/PgUp/PgDn-scroll");
    attroff(COLOR_PAIR(2));

    for (cur = head, num = 0; cur; cur = cur->next, num++) {
	if ((num >= skip) && (num - skip < LINES - 5)) {
	    packets_short(in_packets, sizeof(in_packets), cur->in_packets);
	    packets_short(out_packets, sizeof(out_packets), cur->out_packets);
	    bytes_short(in_bytes, sizeof(in_bytes), cur->in_bytes);
	    bytes_short(out_bytes, sizeof(out_bytes), cur->out_bytes);

	    mvprintw(line++, 0, "%-22s %8s %8s %8s %8s %6u%s %6u%s",
		(opts->mac) ? cur->visible_mac : cur->visible_ip,
		in_packets,
		out_packets,
		in_bytes,
		out_bytes,
		cur->in_rates,
		(opts->kbytes) ? "KB/s" : "Kb/s",
		cur->out_rates,
		(opts->kbytes) ? "KB/s" : "Kb/s");
	}
	total_in_packets  += cur->in_packets;
	total_out_packets += cur->out_packets;
	total_in_bytes    += cur->in_bytes;
	total_out_bytes   += cur->out_bytes;
	total_in_rates    += cur->in_rates;
	total_out_rates   += cur->out_rates;
    }

    attron(COLOR_PAIR(2));
    mvhline(line++, 0, ACS_HLINE, 80);
    mvprintw(line++, 0,"%-22s ", "Total:");
    attroff(COLOR_PAIR(2));

    packets_short(in_packets, sizeof(in_packets), total_in_packets);
    packets_short(out_packets, sizeof(out_packets), total_out_packets);
    bytes_short(in_bytes, sizeof(in_bytes), total_in_bytes);
    bytes_short(out_bytes, sizeof(out_bytes), total_out_bytes);

    printw(
	"%8s %8s %8s %8s %6u%s %6u%s",
	in_packets,
	out_packets,
	in_bytes,
	out_bytes,
	total_in_rates,
	(opts->kbytes) ? "KB/s" : "Kb/s",
	total_out_rates,
	(opts->kbytes) ? "KB/s" : "Kb/s");

    refresh();

    pthread_mutex_unlock(&list_lock);
}

static int delete_inactive(int purge_time)
{
    struct host *cur, *next;
    struct host *prev = NULL;
    struct timeval tv;
    int del = 0;

    pthread_mutex_lock(&list_lock);

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);

    for (cur = head; cur; cur = next) {
	next = cur->next;
	/* Delete hosts which were not updated more than purge_time seconds. */
	if (cur->timestamp + purge_time < tv.tv_sec) {
	    if (prev)
		prev->next = cur->next;
	    else
		head = cur->next;
	    free(cur);
	    hosts_num--;
	    del = 1;
	} else
	    prev = cur;
    }

    pthread_mutex_unlock(&list_lock);

    return del;
}

static void process_packet(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct options *opts = (struct options *) param;
    struct ethhdr *eth = (struct ethhdr *) pkt_data;
    struct iphdr *ip = (struct iphdr *) (pkt_data + ETH_HLEN);
    time_t passed = header->ts.tv_sec - rates_update;

    if ((ip->daddr & opts->mask) == opts->net)
	update_counts(ip->daddr, eth->h_dest, header, RECEIVE, opts->resolve);

    if ((ip->saddr & opts->mask) == opts->net)
	update_counts(ip->saddr, eth->h_source, header, TRANSMIT, opts->resolve);

    if (passed >= 5) {
	rates_update = header->ts.tv_sec;
	update_rates(passed, opts->kbytes);
    }

    if ((header->ts.tv_sec - display_update) >= opts->refresh_time) {
	display_update = header->ts.tv_sec;
	update_display(opts);
    }
}

static void *pcap_thread(void *arg)
{
    struct options *opts = (struct options *) arg;

    pcap_loop(opts->handle, -1, process_packet, (u_char *) opts);

    return NULL;
}

void display(struct options *opts)
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
    display_update = rates_update = tv.tv_sec;

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
	    case 'b':
	    case 'B':
		opts->kbytes = ~opts->kbytes;
		erase();
		update_display(opts);
		break;
	    case 'd':
	    case 'D':
		if (delete_inactive(opts->purge_time)) {
		    skip = 0;
		    erase();
		    update_display(opts);
		}
		break;
	    case 'm':
	    case 'M':
		opts->mac = ~opts->mac;
		erase();
		update_display(opts);
		break;
	    case 'r':
	    case 'R':
		resolve_all_hosts(opts->resolve);
		opts->resolve = ~opts->resolve;
		erase();
		update_display(opts);
		break;
	    case 'q':
	    case 'Q':
		run = FALSE;
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
