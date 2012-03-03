#ifndef MAIN_H
#define MAIN_H

#include "pcap.h"

struct options {
    pcap_t	*handle_in;
    pcap_t	*handle_out;
    char	interface[16];
    char	expression[128];
    u_int8_t	resolve;
    int		port;
    int		header_len;
};

extern struct options opts;

#endif
