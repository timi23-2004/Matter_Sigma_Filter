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
#ifndef PR_LOG_H
#define PR_LOG_H
#include <stdio.h>
#include <stdlib.h>
#include "pr_pcap.h"

typedef struct {
    int length;
    unsigned char src_mac[6];
    unsigned char dest_mac[6];
    unsigned short ethertype;
} log_packet_t;
extern FILE *log_file;
void init_log_file(const char *filename);
void close_log_file();
void log_packet(const struct pcap_pkthdr *header,const packet_info_t *pktinfo);

#endif // PR_LOG_H
