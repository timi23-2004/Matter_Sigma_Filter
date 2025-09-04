#ifndef PR_CLEAN_H
#define PR_CLEAN_H
#include "pr_pcap.h"

void pr_cleanup(pr_pcap_ctx_t *pcap_handle);
void setup_clean_handler(void);
int get_interrupted_flag(void);

#endif // PR_CLEAN_H
