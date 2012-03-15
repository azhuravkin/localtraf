#include <netdb.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include "main.h"
#include "display.h"
#include "resolve.h"
#include "sort.h"

static void resolve_host(struct host *tmp) {
    struct hostent *he;
    struct host *cur;

    if ((he = gethostbyaddr(&tmp->ip_big, 4, AF_INET)))
	snprintf(tmp->ip_ptr, sizeof(tmp->ip_ptr), "%s", he->h_name);
    else
	snprintf(tmp->ip_ptr, sizeof(tmp->ip_ptr), "%s", tmp->ip_str);

    pthread_mutex_lock(&list_lock);

    for (cur = *head.show; cur; cur = cur->next)
	if (cur->ip_big == tmp->ip_big) {
	    strcpy(cur->ip_ptr, tmp->ip_ptr);
	    break;
	}

    sort(head.show, *head.show_num);

    pthread_mutex_unlock(&list_lock);
}

void *resolve_thread(void *arg) {
    struct host *cur;
    struct host tmp;
    struct timespec t;

    t.tv_sec = 0;
    t.tv_nsec = 100000000;

    while (1) {
	memset(&tmp, 0, sizeof(tmp));

	pthread_mutex_lock(&list_lock);

	if (opts.resolve)  {
	    /* Обходим список в поиске неразрешёного хоста и сохраняем его в tmp. */
	    for (cur = *head.show; cur; cur = cur->next)
		if (!cur->ip_ptr[0]) {
		    tmp = *cur;
		    break;
		}

	    pthread_mutex_unlock(&list_lock);

	    if (tmp.ip_big) {
		resolve_host(&tmp);

		if (!opts.port) {
		    erase();
		    update_display();
		}
	    }
	} else
	    pthread_mutex_unlock(&list_lock);

	/* Если неразрешённых хостов не нашли - засыпаем перед новой итерацией. */
	if (!tmp.ip_big)
	    nanosleep(&t, NULL);
    }

    return NULL;
}
