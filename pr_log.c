/*
 * MyProject
 * Copyright (C) 2026 Bandi Timea Evelyne
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pr_log.h"
#include "pr_print.h"

FILE *log_file = NULL;

void init_log_file(const char *filename) {
    log_file = fopen(filename, "a");
    if (!log_file) {
        perror("Failed to open log file");
    }
}

void close_log_file() {
    if (!log_file) {
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
    print_packet_info_logfile(time_str, pktinfo);
}
