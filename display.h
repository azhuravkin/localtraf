#ifndef DISPLAY_H
#define DISPLAY_H

#include <linux/if_ether.h>

enum {
    RECEIVE,
    TRANSMIT
};

void display(struct options *);

#endif
