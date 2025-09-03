#include "pr_pcap.h"
#include "pr_print.h"
#include "pr_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>

FILE *log_file = NULL;

void init_log_file(const char *filename) {
    log_file = fopen(filename, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
}

void close_log_file() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

void log_packet(const struct pcap_pkthdr *header, const packet_info_t *pktinfo) {
    if (!header || !pktinfo) {
        fprintf(stderr, "Invalid header or packet_info in log_packet.\n");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    if (!log_file) {
        init_log_file("log.txt");
    }
    print_packet_info_logfile(time_str, pktinfo);
    close_log_file();
}

