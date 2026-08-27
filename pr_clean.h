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
#ifndef PR_CLEAN_H
#define PR_CLEAN_H
#include "pr_pcap.h"

void pr_cleanup(pr_pcap_ctx_t *pcap_handle);
void setup_clean_handler(void);
int get_interrupted_flag(void);

#endif // PR_CLEAN_H
