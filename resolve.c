#include <netdb.h>
#include <time.h>
#include <string.h>
#include "main.h"
#include "display.h"
#include "resolve.h"
#include "sort.h"

static void resolve_host(struct host *cur) {
    struct hostent *he;

    if (!cur->ip_ptr[0]) {
	if ((he = gethostbyaddr(&cur->ip_big, 4, AF_INET)))
	    snprintf(cur->ip_ptr, sizeof(cur->ip_ptr), "%s", he->h_name);
	else
	    snprintf(cur->ip_ptr, sizeof(cur->ip_ptr), "%s", cur->ip_str);
    }
}

static void resolve_list(struct host **list, int num) {
    int i;

    for (i = 0; i < num; i++)
	resolve_host(list[i]);
}

void *resolve_thread(void *arg) {
    struct host *cur;
    struct timespec t;
    struct host *list[RESOLVE_LIST_SIZE];
    int i;

    t.tv_sec = 0;
    t.tv_nsec = 100000000;

    while (!nanosleep(&t, NULL)) {
	if (opts.resolve)  {
	    pthread_mutex_lock(&list_lock);

	    for (cur = head, i = 0; cur && i < RESOLVE_LIST_SIZE; cur = cur->next)
		if (!cur->ip_ptr[0])
		    list[i++] = cur;

	    pthread_mutex_unlock(&list_lock);

	    if (i) {
		resolve_list(list, i);

		pthread_mutex_lock(&list_lock);
		sort(&head, hosts_num, sort_num, opts.resolve);
		pthread_mutex_unlock(&list_lock);
	    }
	}
    }

    return NULL;
}
