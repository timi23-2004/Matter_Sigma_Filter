#include "pr_pcap.h"
#include "pr_print.h"
#include "pr_log.h"
#include "pr_sig1_case.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

#define MF_SRC_NODE 0x04
#define MF_DST_NODE 0x01
#define MSID_ZERO   0x0000
#define MSF_ZERO    0x00
#define MOP_IDX     17
#define M_MINLEN    8
#define M_NODELEN   8
#define OPCODE_ANNOUNCE 0x30


pr_pcap_ctx_t *pcap_initialize(const char *name, pcap_source_t source_type) {
    char errbuf[PCAP_ERRBUF_SIZE];
    init_log_file("log.txt");
    mac_pair_count_list_init();
    pr_pcap_ctx_t *ctx = malloc(sizeof(pr_pcap_ctx_t));
    if (!ctx) return NULL;
    ctx->window_start_time = 0;
    if (source_type == PCAP_SOURCE_INTERFACE) {
        ctx->handle = pcap_open_live(name, BUFSIZ, 1, 1000, errbuf);
        if (ctx->handle == NULL) {
            fprintf(stderr, "Error opening interface: %s\n", errbuf);
            goto err_open;
        }
    } else {
        ctx->handle = pcap_open_offline(name, errbuf);
        if (ctx->handle == NULL) {
            fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
            goto err_open;
        }
    }
    char filter_exp[] = "ip6 and udp and ((udp src port 5540)or (udp dst port 5540))";
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
    close_log_file("log.txt");
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
    memcpy(pktinfo->eth.dest_mac, packet, 6);
    memcpy(pktinfo->eth.src_mac, packet + 6, 6);
    pktinfo->eth.length = header->len;
    pktinfo->eth.ethertype = ntohs(*(uint16_t *)(packet + 12));
    pktinfo->ip.protocol = packet[20];
    inet_ntop(AF_INET6, packet + 22, pktinfo->ip.src_ip, sizeof(pktinfo->ip.src_ip));
    inet_ntop(AF_INET6, packet + 38, pktinfo->ip.dst_ip, sizeof(pktinfo->ip.dst_ip));
    pktinfo->ip.is_ipv6 = 1;
    int udp_offset = 14 + 40;
    pktinfo->udp.src_port = ntohs(*(uint16_t *)(packet + udp_offset));
    pktinfo->udp.dst_port = ntohs(*(uint16_t *)(packet + udp_offset + 2));

    int matter_offset = 14 + 40 + 8;
    const uint8_t *matter = packet + matter_offset;
    int available = header->len - matter_offset;
    matter_info_t *minfo = &pktinfo->matter;
    memset(minfo, 0, sizeof(matter_info_t));

    int offset = 0;
    if (available >= 8) {
        minfo->message_flags = matter[0];

        minfo->session_id = ntohs(*(uint16_t *)(matter + 1));
        minfo->security_flags = matter[3];

        minfo->message_counter = ntohl(*(uint32_t *)(matter + 4));
        offset = 8;
        minfo->has_source_node_id = 0;
        minfo->has_destination_node_id = 0;
        if (minfo->message_flags & MF_SRC_NODE) {
            if (available >= offset + M_NODELEN) {
                minfo->has_source_node_id = 1;
                minfo->source_node_id = 0;
                for (int i = 0; i < M_NODELEN; ++i)
                    minfo->source_node_id = (minfo->source_node_id << 8) | matter[offset + i];
                offset += M_NODELEN;
            }
        }
        if (minfo->message_flags & MF_DST_NODE) {
            if (available >= offset + M_NODELEN) {
                minfo->has_destination_node_id = 1;
                minfo->destination_node_id = 0;
                for (int i = 0; i < M_NODELEN; ++i)
                    minfo->destination_node_id = (minfo->destination_node_id << 8) | matter[offset + i];
                offset += M_NODELEN;
            }
        }
    }
    if (minfo->session_id == MSID_ZERO && minfo->security_flags == MSF_ZERO && available >= 13) {
        minfo->protocol_opcode = matter[MOP_IDX];
    }
    int payload_offset = matter_offset + offset;
    int payload_len = header->len - payload_offset;
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
    const int window_sec = 30;
    static int first_run = 1;
    if (first_run) {
        mac_pair_count_list_init();
        first_run = 0;
    }
    int result = pcap_next_ex(ctx->handle, &header, &packet);
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


