#ifndef PR_CLEAN_H
#define PR_CLEAN_H
#include "pr_pcap.h"
#include <signal.h>
void pr_cleanup(pr_pcap_ctx_t *pcap_handle);
void setup_clean_handler(void);
extern volatile sig_atomic_t interrupted_flag;
#endif