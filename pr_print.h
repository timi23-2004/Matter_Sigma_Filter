#include "pr_pcap.h"
#ifndef PR_PRINT_H
#define PR_PRINT_H
#include <pcap.h>
#include <stdbool.h>
#include "pr_log.h"
void print_packet_info(const struct pcap_pkthdr *header, const packet_info_t *pktinfo);
void print_packet_info_logfile(const char *time_str, const packet_info_t *pktinfo);
#endif // PR_PRINT_H
