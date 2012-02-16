#ifndef PCAP_H
#define PCAP_H

#include <pcap/pcap.h>
#include <pcap/sll.h>

#define SNAPLEN 64

void pcap_init(void);
void pcap_cancel(void);

#endif
