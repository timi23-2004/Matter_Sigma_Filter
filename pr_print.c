#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>
#include "pr_pcap.h"
#include "pr_print.h"
#include "pr_log.h"

void print_packet_info(const struct pcap_pkthdr *header, const packet_info_t *pktinfo) {
    if (header == NULL || pktinfo == NULL) {
        fprintf(stderr, "Invalid packet header or packet info.\n");
        return;
    }
    printf("Captured a packet with length: %d\n", header->len);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pktinfo->eth.src_mac[0], pktinfo->eth.src_mac[1], pktinfo->eth.src_mac[2], pktinfo->eth.src_mac[3], pktinfo->eth.src_mac[4], pktinfo->eth.src_mac[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pktinfo->eth.dest_mac[0], pktinfo->eth.dest_mac[1], pktinfo->eth.dest_mac[2], pktinfo->eth.dest_mac[3], pktinfo->eth.dest_mac[4], pktinfo->eth.dest_mac[5]);
    printf("UDP Source Port: %u\n", pktinfo->udp.src_port);
    printf("UDP Destination Port: %u\n", pktinfo->udp.dst_port);
    printf("IPv6 Source: %s\n", pktinfo->ip.src_ip);
    printf("IPv6 Destination: %s\n", pktinfo->ip.dst_ip);

    printf("message flags: 0x%02x\n", pktinfo->matter.message_flags);
    printf("session id: 0x%04x\n", pktinfo->matter.session_id);
    printf("security flags: 0x%02x\n", pktinfo->matter.security_flags);
    printf("message counter: 0x%08x\n", pktinfo->matter.message_counter);
    if (pktinfo->matter.has_source_node_id)
    printf("source node id: 0x%016llx\n", (unsigned long long)pktinfo->matter.source_node_id);
    else
        printf("source node id: (not present)\n");
    if (pktinfo->matter.has_destination_node_id)
    printf("destination node id: 0x%016llx\n", (unsigned long long)pktinfo->matter.destination_node_id);
    else
        printf("destination node id: (not present)\n");
    if (pktinfo->matter.session_id == 0x0000 && pktinfo->matter.security_flags == 0x00) {
        printf("protocol opcode: 0x%02x\n", pktinfo->matter.protocol_opcode);
    }
     printf("\n");

}

void print_packet_info_logfile(const char *time_str, const packet_info_t *pktinfo) {
    if (pktinfo == NULL || time_str == NULL) {
        fprintf(stderr, "Invalid log_packet_t pointer or time string.\n");
        return;
    }
    char src_ip[INET6_ADDRSTRLEN] = "";
    char dst_ip[INET6_ADDRSTRLEN] = "";
    strncpy(src_ip, pktinfo->ip.src_ip, sizeof(src_ip));
    strncpy(dst_ip, pktinfo->ip.dst_ip, sizeof(dst_ip));

    char src_mac_str[18], dest_mac_str[18], ethertype_str[8];
    snprintf(src_mac_str, sizeof(src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        pktinfo->eth.src_mac[0], pktinfo->eth.src_mac[1], pktinfo->eth.src_mac[2], pktinfo->eth.src_mac[3], pktinfo->eth.src_mac[4], pktinfo->eth.src_mac[5]);
    snprintf(dest_mac_str, sizeof(dest_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        pktinfo->eth.dest_mac[0], pktinfo->eth.dest_mac[1], pktinfo->eth.dest_mac[2], pktinfo->eth.dest_mac[3], pktinfo->eth.dest_mac[4], pktinfo->eth.dest_mac[5]);
    snprintf(ethertype_str, sizeof(ethertype_str), "%04x", pktinfo->eth.ethertype);
    fprintf(log_file,
        "| %-19s | %-17s | %-17s | %-7s | %-6d | %-6u | %-6u | %-36s | %-36s |\n",
        time_str,
        src_mac_str,
        dest_mac_str,
        ethertype_str,
        pktinfo->eth.length,
        pktinfo->udp.src_port,
        pktinfo->udp.dst_port,
        src_ip,
        dst_ip);
}
