#ifndef PR_CASE_H
#define PR_CASE_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>

void mac_pair_count_list_init(void);
void mac_pair_count_list_uninit(void);
void mac_pair_count_add(const unsigned char *src_mac, const unsigned char *dest_mac);
void mac_pair_count_print_all(void);
bool is_mac_pair_blocked(const unsigned char *src_mac, const unsigned char *dest_mac);
void mac_pair_count_reset_counts(void);

#endif //PR_CASE_H
