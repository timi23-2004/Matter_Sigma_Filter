#ifndef PR_LOG_H
#define PR_LOG_H
#include <stdio.h>
#include <stdlib.h>
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

