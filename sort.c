#include <string.h>
#include "localtraf.h"
#include "sort.h"

static int ip(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return ((*e1)->ip - (*e2)->ip);
}

static int resolve(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return strcmp((*e1)->visible_name, (*e2)->visible_name);
}

static int in_packets(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return ((*e2)->in_packets - (*e1)->in_packets);
}

static int out_packets(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return ((*e2)->out_packets - (*e1)->out_packets);
}

static int in_bytes(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return ((*e2)->in_bytes - (*e1)->in_bytes);
}

static int out_bytes(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return ((*e2)->out_bytes - (*e1)->out_bytes);
}

static int in_rates(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return ((*e2)->in_rates - (*e1)->in_rates);
}

static int out_rates(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;

    return ((*e2)->out_rates - (*e1)->out_rates);
}

void sort(struct host **head, const int num, struct options *opts)
{
    struct host *arr[num];
    struct host *cur;
    int i = 0;

    if (num < 2)
	return;

    for (cur = *head; cur; cur = cur->next)
	arr[i++] = cur;

    switch (opts->sort) {
	case '1':
	    if (opts->resolve)
		qsort(arr, num, sizeof(struct host *), resolve);
	    else
		qsort(arr, num, sizeof(struct host *), ip);
	    break;
	case '2':
	    qsort(arr, num, sizeof(struct host *), in_packets);
	    break;
	case '3':
	    qsort(arr, num, sizeof(struct host *), out_packets);
	    break;
	case '4':
	    qsort(arr, num, sizeof(struct host *), in_bytes);
	    break;
	case '5':
	    qsort(arr, num, sizeof(struct host *), out_bytes);
	    break;
	case '6':
	    qsort(arr, num, sizeof(struct host *), in_rates);
	    break;
	case '7':
	    qsort(arr, num, sizeof(struct host *), out_rates);
	    break;
    }

    *head = arr[0];

    for (i = 0; i < num - 1; i++)
	arr[i]->next = arr[i + 1];

    arr[i]->next = NULL;
}
