#ifndef LOCALTRAF_H
#define LOCALTRAF_H

#include <stdlib.h>
#include <ncurses.h>
#include <pcap.h>

struct host {
    time_t	timestamp;
    char	visible_ip[23];
    char	visible_name[64];
    u_int32_t	ip;
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

struct options {
    pcap_t	*handle_in;
    pcap_t	*handle_out;
    char	*dev;
    FILE	*fp;
    u_int8_t	color;
    u_int8_t	mac;
    u_int8_t	resolve;
    char	*outfile;
    int		sort;
};

#endif
