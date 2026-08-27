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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "pr_clean.h"
#include "pr_pcap.h"

static volatile sig_atomic_t interrupted_flag = 0;

int get_interrupted_flag(void) {
    return interrupted_flag;
}

void pr_cleanup(pr_pcap_ctx_t *pcap_handle) {
    if (pcap_handle) {
        pcap_uninit(pcap_handle);
        printf("pcap_handle cleaned up.\n");
    }
    printf("Program exiting cleanly.\n");
}
static void clean_exit_handler(int signum) {
    interrupted_flag = 1;
}

void setup_clean_handler(void) {
    signal(SIGINT, clean_exit_handler);
    signal(SIGTERM, clean_exit_handler);
}
