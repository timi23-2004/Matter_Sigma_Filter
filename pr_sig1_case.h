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
