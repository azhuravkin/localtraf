#ifndef DISPLAY_H
#define DISPLAY_H

#define timergrow(h, l, u)\
    ((double) h.tv_usec / 1000000 + h.tv_sec > (double) l.tv_usec / 1000000 + l.tv_sec + u)

#include <linux/if_ether.h>

void show_display(struct options *);
void start_daemon(struct options *);

#endif
