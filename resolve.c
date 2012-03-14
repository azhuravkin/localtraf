#include <netdb.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include "main.h"
#include "display.h"
#include "resolve.h"
#include "sort.h"

static void resolve_list(struct host **list, int num) {
    struct hostent *he;
    int i;

    for (i = 0; i < num; i++) {
	if ((he = gethostbyaddr(&list[i]->ip_big, 4, AF_INET)))
	    snprintf(list[i]->ip_ptr, sizeof(list[i]->ip_ptr), "%s", he->h_name);
	else
	    snprintf(list[i]->ip_ptr, sizeof(list[i]->ip_ptr), "%s", list[i]->ip_str);
    }
}

void *resolve_thread(void *arg) {
    struct host *cur;
    struct host *peer;
    struct timespec t;
    struct host *list[RESOLVE_LIST_SIZE];
    int i;

    t.tv_sec = 0;
    t.tv_nsec = 100000000;

    while (1) {
	pthread_mutex_lock(&list_lock);

	if (opts.resolve)  {
	    /* Обходим главный список в поиске неразрешённых хостов и сохраняем их адреса. */
	    for (cur = head, i = 0; cur && i < RESOLVE_LIST_SIZE; cur = cur->next)
		if (!cur->ip_ptr[0])
		    list[i++] = cur;
	    /* Если неразрешённых хостов меньше чем RESOLVE_LIST_SIZE, ищем их в списках пиров. */
	    if (i < RESOLVE_LIST_SIZE)
		for (cur = head; cur && i < RESOLVE_LIST_SIZE; cur = cur->next)
		    for (peer = cur->peers; peer && i < RESOLVE_LIST_SIZE; peer = peer->next)
			if (!peer->ip_ptr[0])
			    list[i++] = peer;

	    pthread_mutex_unlock(&list_lock);

	    if (i) {
		resolve_list(list, i);

		pthread_mutex_lock(&list_lock);

		sort(&head, hosts_num, sort_num);

		pthread_mutex_unlock(&list_lock);

		if (!opts.port) {
		    erase();
		    update_display();
		}
	    }
	} else
	    pthread_mutex_unlock(&list_lock);

	/* Если набран полный массив RESOLVE_LIST_SIZE неразрешённых хостов,
	   то nanosleep() не выполняем а сразу переходим к новой итерации. */
	if (i < RESOLVE_LIST_SIZE)
	    nanosleep(&t, NULL);
    }

    return NULL;
}
