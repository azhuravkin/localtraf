#ifndef DISPLAY_H
#define DISPLAY_H

#define S1 space1, " "
#define S2 space2, " "
#define S3 space3, " "

#define timergrow(h, l, u)\
    ((float) h.tv_usec / 1000000 + h.tv_sec >= (float) l.tv_usec / 1000000 + l.tv_sec + u)

#include <linux/if_ether.h>

enum {
    RECEIVE,
    TRANSMIT
};

void show_display(struct options *);
void start_daemon(struct options *);

#endif
