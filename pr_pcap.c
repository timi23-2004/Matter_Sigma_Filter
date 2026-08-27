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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pr_log.h"
#include "pr_pcap.h"
#include "pr_print.h"
#include "pr_sig1_case.h"

#define MF_SRC_NODE 0x04
#define MF_DST_NODE 0x01
#define MSID_ZERO   0x0000
#define MSF_ZERO    0x00
#define MOP_IDX     17
#define M_MINLEN    8
#define M_NODELEN   8
#define M_OPCODE_MIN_AVAIL 13
#define OPCODE_ANNOUNCE 0x30
#define ETHERNET_HEADER_LEN 14
#define IPV6_HEADER_LEN 40
#define UDP_HEADER_LEN 8
#define MAC_ADDR_LEN 6
#define ETHERTYPE_OFFSET 12
#define IP_PROTOCOL_OFFSET 20
#define IPV6_SRC_OFFSET 22
#define IPV6_DST_OFFSET 38


pr_pcap_ctx_t *pcap_initialize(const char *name, pcap_source_t source_type) {
    char errbuf[PCAP_ERRBUF_SIZE];
    mac_pair_count_list_init();
    pr_pcap_ctx_t *ctx = malloc(sizeof(pr_pcap_ctx_t));
    if (!ctx) return NULL;
    *ctx = (pr_pcap_ctx_t){0};
    if (source_type == PCAP_SOURCE_INTERFACE) {
        ctx->handle = pcap_open_live(name, BUFSIZ, 1, 1000, errbuf);
        if (!ctx->handle) {
            fprintf(stderr, "Error opening interface: %s\n", errbuf);
            goto err_open;
        }
    } else {
        ctx->handle = pcap_open_offline(name, errbuf);
        if (!ctx->handle) {
            fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
            goto err_open;
        }
    }
    char filter_exp[] = "ip6 and udp and ((udp src port 5540) or (udp dst port 5540))";
    if (pcap_compile(ctx->handle, &ctx->fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        goto err_compile;
    }
    if (pcap_setfilter(ctx->handle, &ctx->fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        goto err_filter;
    }
    return ctx;
err_filter:
    pcap_freecode(&ctx->fp);
err_compile:
    pcap_close(ctx->handle);
err_open:
    free(ctx);
    return NULL;
}

void pcap_uninit(pr_pcap_ctx_t *ctx) {
    mac_pair_count_list_uninit();
    if (ctx) {
        pcap_freecode(&ctx->fp);
        if (ctx->handle) {
            pcap_close(ctx->handle);
        }
        free(ctx);
    }
}

static void build_info(const struct pcap_pkthdr *header, const unsigned char *packet, packet_info_t *pktinfo) {
    if (!header || !packet || !pktinfo) {
        fprintf(stderr, "Invalid arguments to build_info.\n");
        return;
    }
    memset(pktinfo, 0, sizeof(packet_info_t));
    memcpy(pktinfo->eth.dest_mac, packet, MAC_ADDR_LEN);
    memcpy(pktinfo->eth.src_mac, packet + MAC_ADDR_LEN, MAC_ADDR_LEN);
    pktinfo->eth.length = header->len;
    pktinfo->eth.ethertype = ntohs(*(uint16_t *)(packet + ETHERTYPE_OFFSET));
    pktinfo->ip.protocol = packet[IP_PROTOCOL_OFFSET];
    inet_ntop(AF_INET6, packet + IPV6_SRC_OFFSET, pktinfo->ip.src_ip, sizeof(pktinfo->ip.src_ip));
    inet_ntop(AF_INET6, packet + IPV6_DST_OFFSET, pktinfo->ip.dst_ip, sizeof(pktinfo->ip.dst_ip));
    pktinfo->ip.is_ipv6 = 1;

    uint8_t udp_offset = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN;
    pktinfo->udp.src_port = ntohs(*(uint16_t *)(packet + udp_offset));
    pktinfo->udp.dst_port = ntohs(*(uint16_t *)(packet + udp_offset + 2));

    uint8_t matter_offset = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN;
    const uint8_t *matter = packet + matter_offset;
    uint16_t available = header->len - matter_offset;
    matter_info_t *minfo = &pktinfo->matter;
    *minfo = (matter_info_t){0};

    uint8_t offset = 0;
    if (available >= M_MINLEN) {
        minfo->message_flags = matter[0];

        minfo->session_id = ntohs(*(uint16_t *)(matter + 1));
        minfo->security_flags = matter[3];

        minfo->message_counter = ntohl(*(uint32_t *)(matter + 4));
    offset = M_MINLEN;
        minfo->has_source_node_id = 0;
        minfo->has_destination_node_id = 0;
        if (minfo->message_flags & MF_SRC_NODE) {
            if (available >= offset + M_NODELEN) {
                minfo->has_source_node_id = 1;
                minfo->source_node_id = 0;
                for (uint8_t i = 0; i < M_NODELEN; ++i)
                    minfo->source_node_id = (minfo->source_node_id << 8) | matter[offset + i];
                offset += M_NODELEN;
            }
        }
        if (minfo->message_flags & MF_DST_NODE) {
            if (available >= offset + M_NODELEN) {
                minfo->has_destination_node_id = 1;
                minfo->destination_node_id = 0;
                for (uint8_t i = 0; i < M_NODELEN; ++i)
                    minfo->destination_node_id = (minfo->destination_node_id << 8) | matter[offset + i];
                offset += M_NODELEN;
            }
        }
    }
    if (minfo->session_id == MSID_ZERO && minfo->security_flags == MSF_ZERO && available >= M_OPCODE_MIN_AVAIL) {
        minfo->protocol_opcode = matter[MOP_IDX];
    }
    uint16_t payload_offset = matter_offset + offset;
    uint16_t payload_len = header->len - payload_offset;
    if (minfo->protocol_opcode == OPCODE_ANNOUNCE && payload_len > 0) {
        mac_pair_count_add(pktinfo->eth.src_mac, pktinfo->eth.dest_mac);
    }
}

bool pcap_run_capture(pr_pcap_ctx_t *ctx) {
    if (!ctx || !ctx->handle) {
        fprintf(stderr, "Invalid pcap context.\n");
        return false;
    }
    struct pcap_pkthdr *header = NULL;
    const unsigned char *packet = NULL;
    const uint16_t window_sec = 30;
    static uint8_t first_run = 1;
    if (first_run) {
        mac_pair_count_list_init();
        first_run = 0;
    }
    uint8_t result = pcap_next_ex(ctx->handle, &header, &packet);
    if (result == 1) {
        packet_info_t pktinfo = {0};
        if (header && packet) {
            if (ctx->window_start_time == 0) {
                ctx->window_start_time = header->ts.tv_sec;
            }
            build_info(header, packet, &pktinfo);
            if (!is_mac_pair_blocked(pktinfo.eth.src_mac, pktinfo.eth.dest_mac)) {
                print_packet_info(header, &pktinfo);
                log_packet(header, &pktinfo);
            }
            if (header->ts.tv_sec - ctx->window_start_time >= window_sec) {
                printf("Window start: %lld\n", (long long)ctx->window_start_time);
                mac_pair_count_print_all();
                mac_pair_count_reset_counts();
                ctx->window_start_time = header->ts.tv_sec;
            }
            return true;
        } else {
            fprintf(stderr, "Null header or packet pointer.\n");
            return false;
        }
    } else if (result == 0) {
        fprintf(stderr, "No packet captured (timeout).\n");
        return false;
    } else if (result == -1) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(ctx->handle));
        return false;
    } else if (result == -2) {
        fprintf(stderr, "End of pcap file reached.\n");
        return false;
    }
    return false;
}
