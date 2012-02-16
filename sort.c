#include <string.h>
#include "main.h"
#include "display.h"
#include "sort.h"

static int ip(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->ip_little < (*e2)->ip_little) return -1;
    if ((*e1)->ip_little > (*e2)->ip_little) return 1;

    return 0;
}

static int hostname(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return strcmp((*e1)->visible_name, (*e2)->visible_name);
}

static int in_packets(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_packets > (*e2)->in_packets) return -1;
    if ((*e1)->in_packets < (*e2)->in_packets) return 1;

    return 0;
}

static int out_packets(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_packets > (*e2)->out_packets) return -1;
    if ((*e1)->out_packets < (*e2)->out_packets) return 1;

    return 0;
}

static int in_bytes(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_bytes > (*e2)->in_bytes) return -1;
    if ((*e1)->in_bytes < (*e2)->in_bytes) return 1;

    return 0;
}

static int out_bytes(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_bytes > (*e2)->out_bytes) return -1;
    if ((*e1)->out_bytes < (*e2)->out_bytes) return 1;

    return 0;
}

static int in_rates(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_rates > (*e2)->in_rates) return -1;
    if ((*e1)->in_rates < (*e2)->in_rates) return 1;

    return 0;
}

static int out_rates(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_rates > (*e2)->out_rates) return -1;
    if ((*e1)->out_rates < (*e2)->out_rates) return 1;

    return 0;
}

static int (*cmp[])(const void *, const void *) =
    { NULL, ip, hostname, in_packets, out_packets, in_bytes, out_bytes, in_rates, out_rates };

void sort() {
    struct host *arr[hosts_num];
    struct host *cur;
    int i = 0;

    if (hosts_num < 2)
	return;

    for (cur = head; cur; cur = cur->next)
	arr[i++] = cur;

    qsort(arr, hosts_num, sizeof(struct host *), cmp[sort_num - 48]); /* convert char number to int */

    head = arr[0];

    for (i = 0; i < hosts_num - 1; i++)
	arr[i]->next = arr[i + 1];

    arr[i]->next = NULL;
}
