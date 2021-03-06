#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <sys/time.h>
#include <unistd.h>
#include <panel.h>
#include "main.h"
#include "pcap.h"
#include "display.h"
#include "sort.h"
#include "http.h"
#include "resolve.h"

struct header head = {
    PTHREAD_MUTEX_INITIALIZER,
    NULL,
    &head.main,
    0,
    &head.main_num,
    '6'
};

static pthread_mutex_t position_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t rates_update;
static struct timeval last_update_in;
static struct timeval last_update_out;
static int skip = 0;
static int position = 0;
static pthread_t pcap_thr_in;
static pthread_t pcap_thr_out;
static pthread_t resolve_thr;

static void search_selected_host(void) {
    struct host *cur;
    int num;

    for (cur = head.main, num = 0; cur; cur = cur->next, num++)
	if (num == position) {
	    head.show = &cur->peers;
	    head.show_num = &cur->peers_num;
	}
}

static void sort_window(void) {
    WINDOW *win = newwin(11, 38, LINES / 2 - 5, COLS / 2 - 19);
    PANEL *panel = new_panel(win);
    int sort_num;

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
    wattroff(win, COLOR_PAIR(2));

    mvwprintw(win, 3, 5, " - sort by IP Address/Hostname");
    mvwprintw(win, 4, 5, " - sort by Incoming Packets");
    mvwprintw(win, 5, 5, " - sort by Outgoing Packets");
    mvwprintw(win, 6, 5, " - sort by Incoming Bytes");
    mvwprintw(win, 7, 5, " - sort by Outgoing Bytes");
    mvwprintw(win, 8, 5, " - sort by Incoming Rates");
    mvwprintw(win, 9, 5, " - sort by Outgoing Rates");

    update_panels();
    doupdate();

    sort_num = wgetch(win);

    pthread_mutex_lock(&head.lock);

    head.sort_num = sort_num;
    sort(head.show, *head.show_num);

    pthread_mutex_unlock(&head.lock);

    del_panel(panel);
    delwin(win);
    erase();
}

static void free_list(struct host **h, u_int32_t *num) {
    struct host *cur, *next;

    for (cur = *h; cur; cur = next) {
	next = cur->next;
	free_list(&cur->peers, &cur->peers_num);
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

static void update_rates(struct host *h, time_t passed) {
    struct host *cur;

    for (cur = h; cur; cur = cur->next) {
	cur->in_rates = ((cur->in_bytes - cur->in_bytes_prev) * 8) / passed;
	cur->out_rates = ((cur->out_bytes - cur->out_bytes_prev) * 8) / passed;
	cur->in_bytes_prev = cur->in_bytes;
	cur->out_bytes_prev = cur->out_bytes;

	update_rates(cur->peers, passed);
    }
}

static struct host *update_counts(struct host **h, u_int32_t *num, u_int32_t ip, const struct pcap_pkthdr *header, int direction) {
    struct host *prev, *cur;

    /* Пропускаем адреса 0.0.0.0 и 255.255.255.255. */
    if (ip == 0 || ip == ~0)
	return NULL;

    /* Ищем запись в списке. */
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
	    return cur;
	}
	prev = cur;
    }

    /* Добавляем новую запись. */
    cur = malloc(sizeof(struct host));
    memset(cur, 0, sizeof(struct host));
    cur->timestamp = header->ts.tv_sec;
    cur->ip_big = ip;
    cur->ip_little = ntohl(ip);
    iptostr(cur->ip_str, ip);

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

    return cur;
}

void update_display(void) {
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

    pthread_mutex_lock(&head.lock);

    attron(COLOR_PAIR(2));
    mvprintw(line++, 0, "IP Address/Hostname  %*s%*sIncoming%*sOutgoing%*sIncoming%*sOutgoing  %*sIncoming  %*sOutgoing",
	s1, " ", s2, " ", s2, " ", s2, " ", s2, " ", s3, " ", s3, " ");
    mvprintw(line++, 0, "                      %*s%*sPackets %*sPackets   %*sBytes   %*sBytes     %*sRates     %*sRates",
	s1, " ", s2, " ", s2, " ", s2, " ", s2, " ", s3, " ", s3, " ");
    attroff(COLOR_PAIR(2));

    pthread_mutex_lock(&position_lock);

    for (cur = *head.show, num = 0; cur; cur = cur->next, num++) {
	if ((num >= skip) && (num - skip < LINES - 5)) {
	    div_1000(in_packets, sizeof(in_packets), cur->in_packets);
	    div_1000(out_packets, sizeof(out_packets), cur->out_packets);
	    div_1024(in_bytes, sizeof(in_bytes), cur->in_bytes);
	    div_1024(out_bytes, sizeof(out_bytes), cur->out_bytes);
	    div_1000(in_rates, sizeof(in_rates), cur->in_rates);
	    div_1000(out_rates, sizeof(out_rates), cur->out_rates);

	    if (num == position)
		attron(COLOR_PAIR(3));

	    mvprintw(line++, 0, "%-*.*s %*s %*s %*s %*s %*sb/s %*sb/s\n",
		21 + s1, 21 + s1, (opts.resolve && cur->ip_ptr[0]) ? cur->ip_ptr : cur->ip_str,
		7 + s2, in_packets,
		7 + s2, out_packets,
		7 + s2, in_bytes,
		7 + s2, out_bytes,
		6 + s3, in_rates,
		6 + s3, out_rates);

	    if (num == position)
		attroff(COLOR_PAIR(3));
	}
	total_in_packets  += cur->in_packets;
	total_out_packets += cur->out_packets;
	total_in_bytes    += cur->in_bytes;
	total_out_bytes   += cur->out_bytes;
	total_in_rates    += cur->in_rates;
	total_out_rates   += cur->out_rates;
    }

    pthread_mutex_unlock(&position_lock);

    attron(COLOR_PAIR(2));
    mvhline(line++, 0, ACS_HLINE, COLS);
    mvprintw(LINES - 1, 1, "Up/Down/PgUp/PgDn/Home/End                R          S       Q");
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

    mvprintw(LINES - 1, 27, "-scroll window");
    mvprintw(LINES - 1, 44, "-resolve");
    mvprintw(LINES - 1, 55, "-sort");
    mvprintw(LINES - 1, 63, "-quit");

    update_panels();
    doupdate();

    pthread_mutex_unlock(&head.lock);
}

static int delete_inactive(struct host **h, u_int32_t *num, time_t timestamp) {
    struct host *cur, *next;
    struct host *prev = NULL;
    int ret = 0;

    for (cur = *h; cur; cur = next) {
	next = cur->next;
	/* Удаляем записи, которые не обновлялись больше 60 секунд. */
	if (cur->timestamp + 60 < timestamp) {
	    if (prev)
		prev->next = cur->next;
	    else
		*h = cur->next;
	    free_list(&cur->peers, &cur->peers_num);
	    free(cur);
	    (*num)--;
	    ret++;
	} else {
	    ret += delete_inactive(&cur->peers, &cur->peers_num, timestamp);
	    prev = cur;
	}
    }

    return ret;
}

static void process_packet_in(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct host *h;
    struct iphdr *ip = (struct iphdr *) (pkt_data + opts.header_len);

    pthread_mutex_lock(&head.lock);

    time_t passed = header->ts.tv_sec - rates_update;

    if ((h = update_counts(&head.main, &head.main_num, ip->saddr, header, PCAP_D_IN)))
	update_counts(&h->peers, &h->peers_num, ip->daddr, header, PCAP_D_OUT);

    if (passed >= 5) {
	rates_update = header->ts.tv_sec;
	update_rates(head.main, passed);

	delete_inactive(&head.main, &head.main_num, rates_update);

	sort(head.show, *head.show_num);

	if (!opts.port) {
	    pthread_mutex_lock(&position_lock);

	    /* Если курсор находится ниже последнего хоста */
	    if (position > *head.show_num - 1)
		/* Устанавливаем его на последний хост */
		position = *head.show_num - 1;

	    /* Если список прокручен вверх и не заполнен внизу*/
	    if (skip && *head.show_num - skip < LINES - 5) {
		/* Прокручиваем его вниз до конца экрана */
		skip -= LINES - 5 - (*head.show_num - skip);
		if (skip < 0)
		    skip = 0;
	    }

	    pthread_mutex_unlock(&position_lock);
	    erase();
	}
    }

    pthread_mutex_unlock(&head.lock);

    if (!opts.port && timergrow(header->ts, last_update_in, 0.1)) {
	last_update_in = header->ts;
	update_display();
    }
}

static void process_packet_out(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct host *h;
    struct iphdr *ip = (struct iphdr *) (pkt_data + opts.header_len);

    pthread_mutex_lock(&head.lock);

    time_t passed = header->ts.tv_sec - rates_update;

    if ((h = update_counts(&head.main, &head.main_num, ip->daddr, header, PCAP_D_OUT)))
	update_counts(&h->peers, &h->peers_num, ip->saddr, header, PCAP_D_IN);

    if (passed >= 5) {
	rates_update = header->ts.tv_sec;
	update_rates(head.main, passed);

	delete_inactive(&head.main, &head.main_num, rates_update);

	sort(head.show, *head.show_num);

	if (!opts.port)
	    pthread_mutex_lock(&position_lock);

	    /* Если курсор находится ниже последнего хоста */
	    if (position > *head.show_num - 1)
		/* Устанавливаем его на последний хост */
		position = *head.show_num - 1;

	    /* Если список прокручен вверх и не заполнен внизу*/
	    if (skip && *head.show_num - skip < LINES - 5) {
		/* Прокручиваем его вниз до конца экрана */
		skip -= LINES - 5 - (*head.show_num - skip);
		if (skip < 0)
		    skip = 0;
	    }

	    pthread_mutex_unlock(&position_lock);
	    erase();
    }

    pthread_mutex_unlock(&head.lock);

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
    pthread_create(&resolve_thr, NULL, resolve_thread, NULL);
    pthread_detach(resolve_thr);
}

static void threads_cancel(void) {
    pthread_cancel(pcap_thr_in);
    pthread_cancel(pcap_thr_out);
    pthread_cancel(resolve_thr);

    pthread_mutex_lock(&head.lock);

    free_list(&head.main, &head.main_num);

    pthread_mutex_unlock(&head.lock);
}

void show_display(void) {
    int run = TRUE;
    struct timeval tv;
    int OLD_LINES;
    int OLD_COLS;
    PANEL *panel;
    int skip_save = 0;
    int position_save = 0;

    pcap_init();
    initscr();

    if ((LINES < 24) || (COLS < 80)) {
	endwin();
	fprintf(stderr, "This program requires a screen size "
			"of at least 80 columns by 24 lines\n");
	exit(EXIT_FAILURE);
    }

    OLD_LINES = LINES;
    OLD_COLS = COLS;

    /* Отключаем показ курсора. */
    curs_set(FALSE);
    /* Не выводим на экран вводимые символы. */
    noecho();
    /* Отслеживаем нажимаемые клавиши. */
    keypad(stdscr, TRUE);
    /* Создаём панель из экрана. Нужно для
       отображения панели поиска поверх основного окна. */
    panel = new_panel(stdscr);

    /* Инициализируем палитру цветов. */
    if (has_colors()) {
	start_color();
	init_pair(1, COLOR_YELLOW, COLOR_BLUE);
	init_pair(2, COLOR_CYAN, COLOR_BLUE);
	init_pair(3, COLOR_YELLOW, COLOR_CYAN);
	bkgd(COLOR_PAIR(1) | A_BOLD);
    }

    /* Получаем текущий timestamp. */
    gettimeofday(&tv, NULL);
    rates_update = tv.tv_sec;

    update_display();

    /* Запускаем pcap_loop нити. */
    threads_init();

    while (run) {
	switch (getch()) {
	    case ERR:
		break;

	    case KEY_UP:
		pthread_mutex_lock(&position_lock);

		/* Если курсор не в самой верхней позиции - поднимаем курсор на 1 позицию. */
		if (position > 0)
		    position--;
		/* Если курсор оказался в пропущенных - прокручиваем список вверх на одну запись. */
		if (skip > position)
		    skip--;

		pthread_mutex_unlock(&position_lock);

		erase();
		update_display();
		break;

	    case KEY_DOWN:
		pthread_mutex_lock(&position_lock);

		/* Если курсор не в самом низу - опускаем его на одну позицию. */
		if (position < *head.show_num - 1)
		    position++;
		/* Если конец списка не влезает в экран и курсор опустился ниже
		   последней строки - прокручиваем список вниз на одну запись. */
		if ((LINES - 5 < *head.show_num - skip) && (position > LINES - 6 + skip))
		    skip++;

		pthread_mutex_unlock(&position_lock);

		erase();
		update_display();
		break;

	    case KEY_PPAGE:
		pthread_mutex_lock(&position_lock);

		/* Если верхние записи вне экрана. */
		if (skip > 0) {
		    /* И если этих записей достаточно для целого экрана. */
		    if (skip >= LINES - 5)
			/* Поднимаем курсор на количество записей в экране. */
			position -= LINES - 5;
		    else
			/* Иначе поднимаем курсор на количетсво пропущенных записей. */
			position -= skip;
		} else
		    position = 0;
		/* Если верхние записи вне экрана. */
		if (skip > 0) {
		    /* Проматываем список на количество записей в экране. */
		    skip -= LINES - 5;
		    if (skip < 0)
			skip = 0;
		}

		pthread_mutex_unlock(&position_lock);

		erase();
		update_display();
		break;

	    case KEY_NPAGE:
		pthread_mutex_lock(&position_lock);

		/* Перемещаем курсор вниз на количетсво записей в экране. */
		position += LINES - 5;
		/* Если курсор стал ниже последней записи. */
		if (position > *head.show_num - 1)
		    /* Перемещаем его на последнюю запись. */
		    position = *head.show_num - 1;
		/* Если конец списка не влезает в экран. */
		if (LINES - 5 < *head.show_num - skip) {
		    /* Перематываем список вниз на количество записей в экране. */
		    skip += LINES - 5;
		    /* Если список промотался на столько, что нижняя часть экрана не занята. */
		    if (*head.show_num - skip < LINES - 5)
			/* Проматываем список так, чтобы последняя запись была внизу экрана. */
			skip -= LINES - 5 - (*head.show_num - skip);
		}

		pthread_mutex_unlock(&position_lock);

		erase();
		update_display();
		break;

	    case KEY_HOME:
		pthread_mutex_lock(&position_lock);

		/* Устанавливаем курсор на первую запись. */
		position = 0;
		/* Отображаем список с первой записи. */
		skip = 0;

		pthread_mutex_unlock(&position_lock);

		erase();
		update_display();
		break;

	    case KEY_END:
		pthread_mutex_lock(&position_lock);

		/* Устанавливаем курсор на последнюю запись. */
		position = *head.show_num - 1;
		/* Прокручиваем список так, чтобы в экран влезла последняя запись. */
		skip = *head.show_num - (LINES - 5);
		if (skip < 0)
		    skip = 0;

		pthread_mutex_unlock(&position_lock);

		erase();
		update_display();
		break;

	    case 'q':
	    case 'Q':
		/* Если мы в главном списке. */
		if (*head.show == head.main) {
		    run = FALSE;
		} else {
		    /* Выход из списка пиров в главный список. */
		    pthread_mutex_lock(&head.lock);

		    head.show = &head.main;
		    head.show_num = &head.main_num;

		    pthread_mutex_unlock(&head.lock);

		    pthread_mutex_lock(&position_lock);

		    /* Восстанавливаем сохранённую позицию курсора и списка. */
		    position = position_save;
		    skip = skip_save;

		    pthread_mutex_unlock(&position_lock);

		    erase();
		    update_display();
		}
		break;

	    case 'r':
	    case 'R':
		pthread_mutex_lock(&head.lock);
		opts.resolve = (opts.resolve) ? FALSE : TRUE;
		sort(head.show, *head.show_num);
		pthread_mutex_unlock(&head.lock);
		update_display();
		break;

	    case 's':
	    case 'S':
		do {
		    sort_window();
		    erase();
		    update_display();
		} while (head.sort_num < '1' || head.sort_num > '7');
		break;

	    case '\n':
		/* Если мы в главном списке. */
		if (*head.show == head.main) {
		    pthread_mutex_lock(&position_lock);
		    pthread_mutex_lock(&head.lock);

		    /* Ищем адрес хоста, на который указывает курсор. */
		    search_selected_host();

		    pthread_mutex_unlock(&head.lock);

		    /* Сохраняем текущую позицию курсора и списка. */
		    position_save = position;
		    position = 0;
		    skip_save = skip;
		    skip = 0;

		    pthread_mutex_unlock(&position_lock);

		    erase();
		    update_display();
		}
		break;

	    default:
		break;
	}

	/* Перерисовываем экран, если размер окна изменился. */
	if ((LINES != OLD_LINES) || (COLS != OLD_COLS)) {
	    OLD_LINES = LINES;
	    OLD_COLS = COLS;

	    pthread_mutex_lock(&position_lock);

	    position = 0;
	    skip = 0;

	    pthread_mutex_unlock(&position_lock);

	    erase();
	    update_display();
	}
    }

    /* Очистка перед выходом. */
    threads_cancel();
    pcap_cancel();

    del_panel(panel);
    endwin();
}

void start_daemon(void) {
    struct timeval tv;

    pcap_init();

    /* Получаем текущий timestamp. */
    gettimeofday(&tv, NULL);
    rates_update = tv.tv_sec;

    /* Создаём pcap_loop нити. */
    threads_init();

    /* Запускаем маленький http сервер. */
    start_http();

    /* Очистка перед выходом. */
    threads_cancel();
    pcap_cancel();
}
