#ifndef DISPLAY_H
#define DISPLAY_H

#define timergrow(h, l, u)\
    ((double) h.tv_usec / 1000000 + h.tv_sec > (double) l.tv_usec / 1000000 + l.tv_sec + u)

#include <linux/if_ether.h>

#include <stdlib.h>
#include <ncurses.h>
#include <netinet/ip.h>

struct host {
    time_t	timestamp;
    char	visible_ip[23];
    char	visible_name[64];
    u_int32_t	ip_big;
    u_int32_t	ip_little;
    u_int32_t	in_packets;
    u_int32_t	out_packets;
    u_int32_t	in_bytes;
    u_int32_t	out_bytes;
    u_int32_t	in_bytes_prev;
    u_int32_t	out_bytes_prev;
    u_int32_t	in_rates;
    u_int32_t	out_rates;
    struct host	*next;
};

extern pthread_mutex_t list_lock;
extern struct host *head;
extern int hosts_num;
extern int sort_num;

void show_display(void);
void start_daemon(void);
void div_1000(char *, size_t, u_int32_t);
void div_1024(char *, size_t, u_int32_t);

#endif
