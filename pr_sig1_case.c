#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include "pr_sig1_case.h"

#define MAX_MAC_PAIRS 100
struct mac_pair_count {
    unsigned char src_mac[6];
    unsigned char dest_mac[6];
    uint16_t count;
    bool blocked;
    LIST_ENTRY(mac_pair_count) next;
};

LIST_HEAD(mac_pair_count_list, mac_pair_count);
static struct mac_pair_count_list mac_pair_counts;

void mac_pair_count_list_init(void)
{
    LIST_INIT(&mac_pair_counts);
}

void mac_pair_count_list_uninit(void)
{
    struct mac_pair_count *item;
    while ((item = LIST_FIRST(&mac_pair_counts)) != NULL) {
        LIST_REMOVE(item, next);
        free(item);
    }
}

void mac_pair_count_add(const unsigned char *src_mac, const unsigned char *dest_mac)
{
    struct mac_pair_count *item;
    LIST_FOREACH(item, &mac_pair_counts, next) {
       if (memcmp(item->src_mac, src_mac, 6) == 0 && memcmp(item->dest_mac, dest_mac, 6) == 0) {
            if (item->blocked) {
                return;
            }
            item->count++;
            if (item->count == MAX_MAC_PAIRS) {
                printf("Packet count for %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x reached maximum threshold of 100\n",
                    item->src_mac[0], item->src_mac[1], item->src_mac[2], item->src_mac[3], item->src_mac[4], item->src_mac[5],
                    item->dest_mac[0], item->dest_mac[1], item->dest_mac[2], item->dest_mac[3], item->dest_mac[4], item->dest_mac[5]);
                char cmd[256];
                snprintf(cmd, sizeof(cmd),
                    "ebtables -A FORWARD -s %02x:%02x:%02x:%02x:%02x:%02x -d %02x:%02x:%02x:%02x:%02x:%02x -j DROP",
                    item->src_mac[0], item->src_mac[1], item->src_mac[2], item->src_mac[3], item->src_mac[4], item->src_mac[5],
                    item->dest_mac[0], item->dest_mac[1], item->dest_mac[2], item->dest_mac[3], item->dest_mac[4], item->dest_mac[5]);
                system(cmd);
                printf("cmd: %s\n", cmd);
                printf("BLOCKED: %02x:%02x:%02x:%02x:%02x:%02x -d %02x:%02x:%02x:%02x:%02x:%02x -j DROP",
                    item->src_mac[0], item->src_mac[1], item->src_mac[2], item->src_mac[3], item->src_mac[4], item->src_mac[5],
                    item->dest_mac[0], item->dest_mac[1], item->dest_mac[2], item->dest_mac[3], item->dest_mac[4], item->dest_mac[5]);
                item->blocked = true;
            }
            return;
        }
    }
    item = malloc(sizeof(struct mac_pair_count));
    if (!item) return;
    memcpy(item->src_mac, src_mac, 6);
    memcpy(item->dest_mac, dest_mac, 6);
    item->count = 1;
    item->blocked = false;
    LIST_INSERT_HEAD(&mac_pair_counts, item, next);
}

void mac_pair_count_print_all(void)
{
    struct mac_pair_count *item;
    printf("Packet counts per MAC pair in this window:\n");
    LIST_FOREACH(item, &mac_pair_counts, next) {
        printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x : %d db\n",
            item->src_mac[0], item->src_mac[1], item->src_mac[2], item->src_mac[3], item->src_mac[4], item->src_mac[5],
            item->dest_mac[0], item->dest_mac[1], item->dest_mac[2], item->dest_mac[3], item->dest_mac[4], item->dest_mac[5],
            item->count);
    }
    printf("\n");
}

bool is_mac_pair_blocked(const unsigned char *src_mac, const unsigned char *dest_mac) {
    struct mac_pair_count *item;
    LIST_FOREACH(item, &mac_pair_counts, next) {
        if (memcmp(item->src_mac, src_mac, 6) == 0 && memcmp(item->dest_mac, dest_mac, 6) == 0) {
            return item->blocked == true;
        }
    }
    return false;
}

void mac_pair_count_reset_counts(void)
{
    struct mac_pair_count *item;
    LIST_FOREACH(item, &mac_pair_counts, next) {
        item->count = 0;
    }
}
