#include "localtraf.h"
#include "sort.h"

static int rates_cmp(const void *p1, const void *p2)
{
    const struct host **e1 = (const struct host **) p1;
    const struct host **e2 = (const struct host **) p2;
    u_int32_t max1 = (*e1)->in_rates;
    u_int32_t max2 = (*e2)->in_rates;

    if (max1 < (*e1)->out_rates)
	max1 = (*e1)->out_rates;

    if (max2 < (*e2)->out_rates)
	max2 = (*e2)->out_rates;

    if (max1 > max2) return -1;
    if (max1 < max2) return 1;

    return 0;
}

void sort(struct host **head, const int num)
{
    struct host *arr[num];
    struct host *cur;
    int i = 0;

    if (num < 2) return;

    for (cur = *head; cur; cur = cur->next)
	arr[i++] = cur;

    qsort(arr, num, sizeof(struct host *), rates_cmp);

    *head = arr[0];

    for (i = 0; i < num - 1; i++)
	arr[i]->next = arr[i + 1];

    arr[i]->next = NULL;
}
