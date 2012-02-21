#include "localtraf.h"
#include "sort.h"

static int ip(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->ip < (*e2)->ip)
	return -1;
    if ((*e1)->ip > (*e2)->ip)
	return 1;

    return 0;
}

static int in_packets(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_packets > (*e2)->in_packets)
	return -1;
    if ((*e1)->in_packets < (*e2)->in_packets)
	return 1;

    return 0;
}

static int out_packets(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_packets > (*e2)->out_packets)
	return -1;
    if ((*e1)->out_packets < (*e2)->out_packets)
	return 1;

    return 0;
}

static int in_bytes(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_bytes > (*e2)->in_bytes)
	return -1;
    if ((*e1)->in_bytes < (*e2)->in_bytes)
	return 1;

    return 0;
}

static int out_bytes(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_bytes > (*e2)->out_bytes)
	return -1;
    if ((*e1)->out_bytes < (*e2)->out_bytes)
	return 1;

    return 0;
}

static int in_rates(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->in_rates > (*e2)->in_rates)
	return -1;
    if ((*e1)->in_rates < (*e2)->in_rates)
	return 1;

    return 0;
}

static int out_rates(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    if ((*e1)->out_rates > (*e2)->out_rates)
	return -1;
    if ((*e1)->out_rates < (*e2)->out_rates)
	return 1;

    return 0;
}

static int(*cmp[7])(const void *, const void *) = {ip, in_packets, out_packets, in_bytes, out_bytes, in_rates, out_rates};

void sort(struct host **head, const int num, struct options *opts)
{
    struct host *arr[num];
    struct host *cur;
    int i = 0;

    if (num < 2)
	return;

    for (cur = *head; cur; cur = cur->next)
	arr[i++] = cur;

    qsort(arr, num, sizeof(struct host *), cmp[opts->sort]);

    *head = arr[0];

    for (i = 0; i < num - 1; i++)
	arr[i]->next = arr[i + 1];

    arr[i]->next = NULL;
}
