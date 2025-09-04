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
