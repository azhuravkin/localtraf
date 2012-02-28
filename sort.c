#include <string.h>
#include "main.h"
#include "display.h"
#include "sort.h"

static int ip(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->ip_ptr[0] && (*e2)->ip_ptr[0])
	return strcmp((*e1)->ip_ptr, (*e2)->ip_ptr);
    else if ((*e1)->ip_ptr[0])
	return -1;
    else if ((*e2)->ip_ptr[0])
	return 1;

    if ((*e1)->ip_little < (*e2)->ip_little)
	return -1;
    if ((*e1)->ip_little > (*e2)->ip_little)
	return 1;

    return 0;
}

static int in_packets(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_packets > (*e2)->in_packets)
	return -1;
    if ((*e1)->in_packets < (*e2)->in_packets)
	return 1;

    return 0;
}

static int out_packets(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_packets > (*e2)->out_packets)
	return -1;
    if ((*e1)->out_packets < (*e2)->out_packets)
	return 1;

    return 0;
}

static int in_bytes(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_bytes > (*e2)->in_bytes)
	return -1;
    if ((*e1)->in_bytes < (*e2)->in_bytes)
	return 1;

    return 0;
}

static int out_bytes(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_bytes > (*e2)->out_bytes)
	return -1;
    if ((*e1)->out_bytes < (*e2)->out_bytes)
	return 1;

    return 0;
}

static int in_rates(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_rates > (*e2)->in_rates)
	return -1;
    if ((*e1)->in_rates < (*e2)->in_rates)
	return 1;

    return 0;
}

static int out_rates(const void *p1, const void *p2) {
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_rates > (*e2)->out_rates)
	return -1;
    if ((*e1)->out_rates < (*e2)->out_rates)
	return 1;

    return 0;
}

static int (*cmp[])(const void *, const void *) =
    { NULL, ip, in_packets, out_packets, in_bytes, out_bytes, in_rates, out_rates };

void sort(struct host **h, const int num) {
    struct host *arr[num];
    struct host *cur;
    int i = 0;

    if (num < 2)
	return;

    for (cur = *h; cur; cur = cur->next)
	arr[i++] = cur;

    qsort(arr, num, sizeof(struct host *), cmp[sort_num - 48]); /* convert char number to int */

    *h = arr[0];

    for (i = 0; i < num - 1; i++)
	arr[i]->next = arr[i + 1];

    arr[i]->next = NULL;
}
