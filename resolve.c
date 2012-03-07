#include <netdb.h>
#include "display.h"
#include "resolve.h"

void resolve_host(struct host *cur) {
    struct hostent *he;

    if (!cur->ip_ptr[0] && (he = gethostbyaddr(&cur->ip_big, 4, AF_INET)))
	snprintf(cur->ip_ptr, sizeof(cur->ip_ptr), "%s", he->h_name);
}

void resolve_all_hosts(void) {
    struct host *cur;

    for (cur = head; cur; cur = cur->next) {
	resolve_host(cur);
    }
}
