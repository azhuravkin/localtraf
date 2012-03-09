#include <netdb.h>
#include <time.h>
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

void *resolve_thread(void *arg) {
    struct host *cur;
    struct timespec t;

    t.tv_sec = 0;
    t.tv_nsec = 100000000;

    while (!nanosleep(&t, NULL)) {
	if (opts.resolve)  {
	    pthread_mutex_lock(&list_lock);

	    for (cur = head; cur; cur = cur->next) {
		if (!cur->ip_ptr[0])
		    resolve_host(cur);
	    }

	    sort(&head, hosts_num, sort_num, opts.resolve);

	    pthread_mutex_unlock(&list_lock);
	}
    }

    return NULL;
}
