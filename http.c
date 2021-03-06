#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "main.h"
#include "display.h"
#include "http.h"
#include "pcap.h"
#include "resolve.h"
#include "sort.h"

static void *reply(void *arg) {
    int *sd = arg;
    int len = 0;
    int i = 0;
    struct host *cur;
    char buffer[65536];
    char in_packets[9];
    char out_packets[9];
    char in_bytes[9];
    char out_bytes[9];
    char in_rates[9];
    char out_rates[9];
    char request[2048];
    char url[128];
    char *p;
    char *saveptr;
    char host[16] = "";
    int refresh = 5;
    char sort_num = '6';
    int resolve = opts.resolve;
    u_int32_t total_in_packets  = 0;
    u_int32_t total_out_packets = 0;
    u_int32_t total_in_bytes    = 0;
    u_int32_t total_out_bytes   = 0;
    u_int32_t total_in_rates    = 0;
    u_int32_t total_out_rates   = 0;

    memset(buffer, '\0', sizeof(buffer));
    memset(request, '\0', sizeof(request));
    memset(url, '\0', sizeof(url));

    while (recv(*sd, buffer, sizeof(buffer), 0) > 0) {
	/* Save string to request[] */
	strncat(request, buffer, sizeof(request));
	memset(buffer, '\0', sizeof(buffer));

	/* If the query ends \r\n\r\n - break */
	if (!strcmp(&request[strlen(request) - 4], "\r\n\r\n"))
	    break;
    }

    /* Analyze the query string */
    for (p = strtok_r(request, "\r\n", &saveptr); p; p = strtok_r(NULL, "\r\n", &saveptr)) {
	if (sscanf(p, "GET %64s HTTP/", url) == 1) {
	    char *params;
	    char *option;
	    char *save;

	    if ((params = strchr(url, '?')) && ++params) {
		for (option = strtok_r(params, "&", &save); option; option = strtok_r(NULL, "&", &save)) {
		    sscanf(option, "refresh=%d", &refresh);
		    sscanf(option, "resolve=%d", &resolve);
		    sscanf(option, "sort=%c", &sort_num);
		    sscanf(option, "host=%15s", host);
		}
	    }
	}
    }

    if (url[0] == '\0') {
	len = snprintf(buffer, sizeof(buffer), "Invalid request\n");
	send(*sd, buffer, len, 0);
	close(*sd);

	return NULL;
    }

    len = snprintf(buffer, sizeof(buffer),
	"HTTP/1.0 200 OK\n"
	"Content-Type: text/html\n\n"
	"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
	"<html>\n<head>\n<meta http-equiv=\"refresh\" content=\"%d\" url=\"/\" />\n"
	"<style type=\"text/css\">\n"
	"body {font-family:Arial;font-size:14px;}\n"
	".header {background-color:#dddddd;text-align:center;border-right:1px solid #666666;border-bottom:1px solid #666666;}\n"
	".data1 {text-align:left;background-color:lavender;border-right:1px solid #6A5ACD;border-bottom:1px solid #6A5ACD;}\n"
	".data2 {text-align:right;background-color:lavender;border-right:1px solid #6A5ACD;border-bottom:1px solid #6A5ACD;}\n"
	"a {color:#0000FF;text-decoration:none;}\n"
	"</style>\n"
	"<title>Localtraf on %s</title>\n</head>\n<body>\n"
	"<table align='center'>\n<tr>\n"
	"<th></th>"
	"<th class='header'><a href=\"?sort=1&refresh=%d&resolve=%d&host=%s\">IP Address/Hostname</a></th>"
	"<th class='header'><a href=\"?sort=2&refresh=%d&resolve=%d&host=%s\">Incoming Packets</a></th>"
	"<th class='header'><a href=\"?sort=3&refresh=%d&resolve=%d&host=%s\">Outgoing Packets</a></th>"
	"<th class='header'><a href=\"?sort=4&refresh=%d&resolve=%d&host=%s\">Incoming Bytes</a></th>"
	"<th class='header'><a href=\"?sort=5&refresh=%d&resolve=%d&host=%s\">Outgoing Bytes</a></th>"
	"<th class='header'><a href=\"?sort=6&refresh=%d&resolve=%d&host=%s\">Incoming Rates</a></th>"
	"<th class='header'><a href=\"?sort=7&refresh=%d&resolve=%d&host=%s\">Outgoing Rates</a></th>\n</tr>\n",
	refresh, opts.interface,
	refresh, resolve, host,
	refresh, resolve, host,
	refresh, resolve, host,
	refresh, resolve, host,
	refresh, resolve, host,
	refresh, resolve, host,
	refresh, resolve, host);

    pthread_mutex_lock(&head.lock);

    if (resolve != opts.resolve)
	opts.resolve = resolve;

    if (strlen(host)) {
	for (cur = head.main; cur; cur = cur->next) {
	    if (!strcmp(cur->ip_str, host)) {
		head.show = &cur->peers;
		head.show_num = &cur->peers_num;
	    }
	}
    } else {
	head.show = &head.main;
	head.show_num = &head.main_num;
    }

    if (sort_num != head.sort_num && sort_num > '0' && sort_num < '8') {
	head.sort_num = sort_num;
	sort(head.show, *head.show_num);
    }

    for (cur = *head.show; cur; cur = cur->next) {
	div_1000(in_packets, sizeof(in_packets), cur->in_packets);
	div_1000(out_packets, sizeof(out_packets), cur->out_packets);
	div_1024(in_bytes, sizeof(in_bytes), cur->in_bytes);
	div_1024(out_bytes, sizeof(out_bytes), cur->out_bytes);
	div_1000(in_rates, sizeof(in_rates), cur->in_rates);
	div_1000(out_rates, sizeof(out_rates), cur->out_rates);

	if (*head.show == head.main)
	    snprintf(url, sizeof(url), "<a href=\"?sort=%c&refresh=%d&resolve=%d&host=%s\">%s</a>",
		head.sort_num, refresh, resolve, cur->ip_str, (resolve && cur->ip_ptr[0]) ? cur->ip_ptr : cur->ip_str);
	else
	    snprintf(url, sizeof(url), "%s", (resolve && cur->ip_ptr[0]) ? cur->ip_ptr : cur->ip_str);

	len += snprintf(buffer + len, sizeof(buffer) - len,
	    "<tr>\n<td class='data2'>%d</td>"
	    "<td class='data1'>%s</td>"
	    "<td class='data2'>%s</td>"
	    "<td class='data2'>%s</td>"
	    "<td class='data2'>%s</td>"
	    "<td class='data2'>%s</td>"
	    "<td class='data2'>%sb/s</td>"
	    "<td class='data2'>%sb/s</td>\n</tr>\n",
	    ++i, url, in_packets, out_packets, in_bytes, out_bytes, in_rates, out_rates);
	total_in_packets  += cur->in_packets;
	total_out_packets += cur->out_packets;
	total_in_bytes    += cur->in_bytes;
	total_out_bytes   += cur->out_bytes;
	total_in_rates    += cur->in_rates;
	total_out_rates   += cur->out_rates;
    }

    pthread_mutex_unlock(&head.lock);

    len += snprintf(buffer + len, sizeof(buffer) - len, "<tr>\n<td></td><td class='data1'>Total:</td>");

    div_1000(in_packets, sizeof(in_packets), total_in_packets);
    div_1000(out_packets, sizeof(out_packets), total_out_packets);
    div_1024(in_bytes, sizeof(in_bytes), total_in_bytes);
    div_1024(out_bytes, sizeof(out_bytes), total_out_bytes);
    div_1000(in_rates, sizeof(in_rates), total_in_rates);
    div_1000(out_rates, sizeof(out_rates), total_out_rates);

    len += snprintf(buffer + len, sizeof(buffer) - len,
	"<td class='data2'>%s</td>"
	"<td class='data2'>%s</td>"
	"<td class='data2'>%s</td>"
	"<td class='data2'>%s</td>"
	"<td class='data2'>%sb/s</td>"
	"<td class='data2'>%sb/s</td>\n"
	"</tr></table>\n</body>\n</html>\n",
	in_packets, out_packets, in_bytes, out_bytes, in_rates, out_rates);

    send(*sd, buffer, len, 0);
    close(*sd);

    return NULL;
}

void start_http(void) {
    struct sockaddr_in self;
    int local_sd;
    int set_flag;

    if ((local_sd = socket(PF_INET, SOCK_STREAM, 0)) == EOF) {
	fprintf(stderr, "Error creating socket\n");
	exit(EXIT_FAILURE);
    }

    set_flag = 1;
    setsockopt(local_sd, SOL_SOCKET, SO_REUSEADDR, &set_flag, sizeof(set_flag));

    memset(&self, 0, sizeof(self));
    self.sin_family = AF_INET;
    self.sin_port = htons(opts.port);
    self.sin_addr.s_addr = INADDR_ANY;

    if (bind(local_sd, (struct sockaddr *) &self, sizeof(self))) {
	fprintf(stderr, "Error binding to port: %d\n", opts.port);
	exit(EXIT_FAILURE);
    }

    if (listen(local_sd, 20)) {
	fprintf(stderr, "Error in listen port: %d\n", opts.port);
	exit(EXIT_FAILURE);
    }

    while (1) {
	int client_sd;
	struct sockaddr_in client;
	socklen_t len = sizeof(client);
	pthread_t thread;

	client_sd = accept(local_sd, (struct sockaddr *) &client, &len);

	if (client_sd > 0) {
	    /* Create new thread. */
	    pthread_create(&thread, NULL, reply, &client_sd);
	    pthread_detach(thread);
	}
    }

    close(local_sd);
}
