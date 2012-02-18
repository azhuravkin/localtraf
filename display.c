#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <sys/time.h>
#include <unistd.h>
#include <panel.h>
#include "main.h"
#include "pcap.h"
#include "display.h"
#include "sort.h"
#include "http.h"

pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
struct host *head = NULL;
int hosts_num = 0;
int sort_num = '6';

static time_t rates_update;
static struct timeval last_update_in;
static struct timeval last_update_out;
static int skip = 0;
static pthread_t pcap_thr_in;
static pthread_t pcap_thr_out;

static void sort_window(void) {
    WINDOW *win = newwin(12, 38, LINES / 2 - 5, COLS / 2 - 19);
    PANEL *panel = new_panel(win);

    if (opts.color)
	wbkgdset(win, COLOR_PAIR(1) | A_BOLD);

    werase(win);

    wattron(win, COLOR_PAIR(2));
    box(win, 0 , 0);
    mvwprintw(win, 1, 8, "Select sort criterion:");
    mvwprintw(win, 3, 4, "1");
    mvwprintw(win, 4, 4, "2");
    mvwprintw(win, 5, 4, "3");
    mvwprintw(win, 6, 4, "4");
    mvwprintw(win, 7, 4, "5");
    mvwprintw(win, 8, 4, "6");
    mvwprintw(win, 9, 4, "7");
    mvwprintw(win, 10, 4, "8");
    wattroff(win, COLOR_PAIR(2));

    mvwprintw(win, 3, 5, " - sort by IP Address");
    mvwprintw(win, 4, 5, " - sort by Hostname");
    mvwprintw(win, 5, 5, " - sort by Incoming Packets");
    mvwprintw(win, 6, 5, " - sort by Outgoing Packets");
    mvwprintw(win, 7, 5, " - sort by Incoming Bytes");
    mvwprintw(win, 8, 5, " - sort by Outgoing Bytes");
    mvwprintw(win, 9, 5, " - sort by Incoming Rates");
    mvwprintw(win, 10, 5, " - sort by Outgoing Rates");

    update_panels();
    doupdate();

    sort_num = wgetch(win);

    del_panel(panel);
    delwin(win);
    erase();
}

static void free_list(struct host **h, int *num) {
    struct host *cur, *next;

    for (cur = *h; cur; cur = next) {
	next = cur->next;
	free(cur);
    }

    *h = NULL;
    *num = 0;
}

void div_1000(char *dst, size_t size, u_int32_t packets) {
    if (packets > 100000)
	snprintf(dst, size, "%uK", packets / 1000);
    else
	snprintf(dst, size, "%u", packets);
}

void div_1024(char *dst, size_t size, u_int32_t bytes) {
    if (bytes > 102400)
	snprintf(dst, size, "%uK", bytes / 1024);
    else
	snprintf(dst, size, "%u", bytes);
}

static void iptostr(char *dst, u_int32_t ip) {
    struct in_addr addr;

    addr.s_addr = ip;

    sprintf(dst, "%s", inet_ntoa(addr));
}

static void resolve_host(struct host *cur) {
    struct hostent *he;

    if (!cur->visible_name[0] && (he = gethostbyaddr(&cur->ip_big, 4, AF_INET)))
	snprintf(cur->visible_name, sizeof(cur->visible_name), "%s", he->h_name);
}

static void resolve_all_hosts(void) {
    struct host *cur;

    for (cur = head; cur; cur = cur->next) {
	resolve_host(cur);
    }
}

static void update_rates(time_t passed) {
    struct host *cur;

    for (cur = head; cur; cur = cur->next) {
	cur->in_rates = ((cur->in_bytes - cur->in_bytes_prev) * 8) / passed;
	cur->out_rates = ((cur->out_bytes - cur->out_bytes_prev) * 8) / passed;
	cur->in_bytes_prev = cur->in_bytes;
	cur->out_bytes_prev = cur->out_bytes;
    }
}

static struct host *update_counts(struct host **h, int *num, u_int32_t ip, const struct pcap_pkthdr *header, int direction) {
    struct host *prev, *cur;

    /* Skip 0.0.0.0 and 255.255.255.255 addresses. */
    if (ip == 0 || ip == ~0)
	return NULL;

    pthread_mutex_lock(&list_lock);

    /* Search host in list. */
    for (cur = *h; cur; cur = cur->next) {
	if (cur->ip_big == ip) {
	    cur->timestamp = header->ts.tv_sec;

	    switch (direction) {
		case PCAP_D_IN:
		    cur->out_bytes += header->len;
		    cur->out_packets++;
		    break;
		case PCAP_D_OUT:
		    cur->in_bytes += header->len;
		    cur->in_packets++;
		    break;
	    }

	    pthread_mutex_unlock(&list_lock);

	    return cur;
	}
	prev = cur;
    }

    /* Add new host. */
    cur = malloc(sizeof(struct host));
    memset(cur, 0, sizeof(struct host));
    cur->timestamp = header->ts.tv_sec;
    cur->ip_big = ip;
    cur->ip_little = ntohl(ip);
    iptostr(cur->visible_ip, ip);

    if (opts.resolve)
	resolve_host(cur);

    switch (direction) {
	case PCAP_D_IN:
	    cur->out_bytes += header->len;
	    cur->out_packets++;
	    break;
	case PCAP_D_OUT:
	    cur->in_bytes += header->len;
	    cur->in_packets++;
	    break;
    }

    if (*h == NULL)
	*h = cur;
    else
	prev->next = cur;

    (*num)++;

    sort(h, *num);

    pthread_mutex_unlock(&list_lock);

    return cur;
}

static void update_display(void) {
    struct host *cur;
    int num, line = 0;
    char in_packets[9];
    char out_packets[9];
    char in_bytes[9];
    char out_bytes[9];
    char in_rates[9];
    char out_rates[9];
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
    mvprintw(line++, 0, "IP Address/Hostname  %*s%*sIncoming%*sOutgoing%*sIncoming%*sOutgoing  %*sIncoming  %*sOutgoing",
	s1, " ", s2, " ", s2, " ", s2, " ", s2, " ", s3, " ", s3, " ");
    mvprintw(line++, 0, "                      %*s%*sPackets %*sPackets   %*sBytes   %*sBytes     %*sRates     %*sRates",
	s1, " ", s2, " ", s2, " ", s2, " ", s2, " ", s3, " ", s3, " ");
    attroff(COLOR_PAIR(2));

    for (cur = head, num = 0; cur; cur = cur->next, num++) {
	if ((num >= skip) && (num - skip < LINES - 5)) {
	    div_1000(in_packets, sizeof(in_packets), cur->in_packets);
	    div_1000(out_packets, sizeof(out_packets), cur->out_packets);
	    div_1024(in_bytes, sizeof(in_bytes), cur->in_bytes);
	    div_1024(out_bytes, sizeof(out_bytes), cur->out_bytes);
	    div_1000(in_rates, sizeof(in_rates), cur->in_rates);
	    div_1000(out_rates, sizeof(out_rates), cur->out_rates);

	    mvprintw(line++, 0, "%-*.*s %*s %*s %*s %*s %*sb/s %*sb/s\n",
		21 + s1, 21 + s1, (opts.resolve && cur->visible_name[0]) ? cur->visible_name : cur->visible_ip,
		7 + s2, in_packets,
		7 + s2, out_packets,
		7 + s2, in_bytes,
		7 + s2, out_bytes,
		6 + s3, in_rates,
		6 + s3, out_rates);
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
    mvprintw(LINES - 1, 1, "Up/Down/PgUp/PgDn                R          S       Q");
    mvprintw(line++, 0,"%-*s ", 21 + s1, "Total:");
    attroff(COLOR_PAIR(2));

    div_1000(in_packets, sizeof(in_packets), total_in_packets);
    div_1000(out_packets, sizeof(out_packets), total_out_packets);
    div_1024(in_bytes, sizeof(in_bytes), total_in_bytes);
    div_1024(out_bytes, sizeof(out_bytes), total_out_bytes);
    div_1000(in_rates, sizeof(in_rates), total_in_rates);
    div_1000(out_rates, sizeof(out_rates), total_out_rates);

    printw("%*s %*s %*s %*s %*sb/s %*sb/s\n",
	7 + s2, in_packets,
	7 + s2, out_packets,
	7 + s2, in_bytes,
	7 + s2, out_bytes,
	6 + s3, in_rates,
	6 + s3, out_rates);

    mvprintw(LINES - 1, 18, "-scroll window");
    mvprintw(LINES - 1, 35, "-resolve");
    mvprintw(LINES - 1, 46, "-sort");
    mvprintw(LINES - 1, 54, "-quit");

    update_panels();
    doupdate();

    pthread_mutex_unlock(&list_lock);
}

static void delete_inactive(struct host **h, int *num) {
    struct host *cur, *next;
    struct host *prev = NULL;
    struct timeval tv;

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);

    for (cur = *h; cur; cur = next) {
	next = cur->next;
	/* Delete hosts which were not updated more than 60 seconds. */
	if (cur->timestamp + 60 < tv.tv_sec) {
	    if (prev)
		prev->next = cur->next;
	    else
		*h = cur->next;
	    free_list(&cur->peers, &cur->peers_num);
	    free(cur);
	    (*num)--;
	} else {
	    delete_inactive(&cur->peers, &cur->peers_num);
	    prev = cur;
	}
    }

    sort(h, *num);
}

static void process_packet_in(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct host *cur;
    struct iphdr *ip = (struct iphdr *) (pkt_data + opts.header_len);
    time_t passed = header->ts.tv_sec - rates_update;

    cur = update_counts(&head, &hosts_num, ip->saddr, header, PCAP_D_IN);
    update_counts(&cur->peers, &cur->peers_num, ip->daddr, header, PCAP_D_OUT);

    if (passed >= 5) {
	pthread_mutex_lock(&list_lock);

	rates_update = header->ts.tv_sec;
	update_rates(passed);
	delete_inactive(&head, &hosts_num);
	erase();

	pthread_mutex_unlock(&list_lock);
    }

    if (!opts.port && timergrow(header->ts, last_update_in, 0.1)) {
	last_update_in = header->ts;
	update_display();
    }
}

static void process_packet_out(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct host *cur;
    struct iphdr *ip = (struct iphdr *) (pkt_data + opts.header_len);
    time_t passed = header->ts.tv_sec - rates_update;

    cur = update_counts(&head, &hosts_num, ip->daddr, header, PCAP_D_OUT);
    update_counts(&cur->peers, &cur->peers_num, ip->saddr, header, PCAP_D_IN);

    if (passed >= 5) {
	pthread_mutex_lock(&list_lock);

	rates_update = header->ts.tv_sec;
	update_rates(passed);
	delete_inactive(&head, &hosts_num);
	erase();

	pthread_mutex_unlock(&list_lock);
    }

    if (!opts.port && timergrow(header->ts, last_update_out, 0.1)) {
	last_update_out = header->ts;
	update_display();
    }
}

static void *pcap_thread_in(void *arg) {
    pcap_loop(opts.handle_in, -1, process_packet_in, NULL);

    return NULL;
}

static void *pcap_thread_out(void *arg) {
    pcap_loop(opts.handle_out, -1, process_packet_out, NULL);

    return NULL;
}

static void threads_init(void) {
    pthread_create(&pcap_thr_in, NULL, pcap_thread_in, NULL);
    pthread_detach(pcap_thr_in);
    pthread_create(&pcap_thr_out, NULL, pcap_thread_out, NULL);
    pthread_detach(pcap_thr_out);
}

static void threads_cancel(void) {
    pthread_cancel(pcap_thr_in);
    pthread_cancel(pcap_thr_out);

    pthread_mutex_lock(&list_lock);

    free_list(&head, &hosts_num);

    pthread_mutex_unlock(&list_lock);
}

void show_display(void) {
    int run = TRUE;
    struct timeval tv;
    int OLD_LINES = LINES;
    int OLD_COLS = COLS;
    PANEL *panel;

    /* Start pcap */
    pcap_init();

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
    if ((opts.color) && has_colors()) {
	start_color();
	init_pair(1, COLOR_YELLOW, COLOR_BLUE);
	init_pair(2, COLOR_CYAN, COLOR_BLUE);
	bkgd(COLOR_PAIR(1) | A_BOLD);
    }

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);
    rates_update = tv.tv_sec;

    update_display();

    /* Create pcap_loop threads. */
    threads_init();

    while (run) {
	switch (getch()) {
	    case ERR:
		break;
	    case KEY_UP:
		if (skip > 0) {
		    skip--;
		    erase();
		    update_display();
		}
		break;
	    case KEY_DOWN:
		if ((LINES - 5) < (hosts_num - skip)) {
		    skip++;
		    erase();
		    update_display();
		}
		break;
	    case KEY_PPAGE:
		if (skip > 0) {
		    skip -= LINES - 5;
		    if (skip < 0)
			skip = 0;
		    erase();
		    update_display();
		}
		break;
	    case KEY_NPAGE:
		if ((LINES - 5) < (hosts_num - skip)) {
		    skip += LINES - 5;
		    erase();
		    update_display();
		}
		break;
	    case 'q':
	    case 'Q':
		run = FALSE;
		break;
	    case 'r':
	    case 'R':
		if (!opts.resolve)
		    resolve_all_hosts();
		opts.resolve = (opts.resolve) ? FALSE : TRUE;
		erase();
		update_display();
		break;
	    case 's':
	    case 'S':
		do {
		    sort_window();
		    erase();
		    update_display();
		} while (sort_num < '1' || sort_num > '8');
		pthread_mutex_lock(&list_lock);
		sort(&head, hosts_num);
		pthread_mutex_unlock(&list_lock);
		update_display();
		break;
	    default:
		break;
	}

	/* Update display if screen is resized. */
	if ((LINES != OLD_LINES) || (COLS != OLD_COLS)) {
	    OLD_LINES = LINES;
	    OLD_COLS = COLS;
	    erase();
	    update_display();
	}
    }

    /* Cleanup. */
    threads_cancel();
    pcap_cancel();

    del_panel(panel);
    endwin();
}

void start_daemon(void) {
    struct timeval tv;

    pcap_init();

    /* Get current timestamp. */
    gettimeofday(&tv, NULL);
    rates_update = tv.tv_sec;

    /* Create pcap_loop threads. */
    threads_init();

    /* Start small http server. */
    start_http();

    /* Cleanup. */
    threads_cancel();
    pcap_cancel();
}
