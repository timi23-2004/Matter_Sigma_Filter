#include "pr_pcap.h"
#include "pr_clean.h"
#include "pr_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]) {
    int ret = EXIT_SUCCESS;
    pr_pcap_ctx_t *pcap_handle = NULL;
    pcap_source_t source;
    const char *source_name = NULL;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <source_type: interface|file> <name>\n", argv[0]);
        goto err_cleanup;
    }

    if (strcmp(argv[1], "interface") == 0) {
        source = PCAP_SOURCE_INTERFACE;
    } else if (strcmp(argv[1], "file") == 0) {
        source = PCAP_SOURCE_FILE;
    } else {
        fprintf(stderr, "Unknown source type: %s\n", argv[1]);
        goto err_cleanup;
    }
    source_name = argv[2];
    pcap_handle = pcap_initialize(source_name, source);
    init_log_file("log.txt");
    if (pcap_handle == NULL) {
        fprintf(stderr, "Could not start packet capture on source: %s\n", source_name);
        goto err_pcap;
    }
    printf("Successfully initialized pcap on source: %s\n", source_name);
    setup_clean_handler();
    printf("Starting packet capture...\n");

    while (!interrupted_flag) {
        if (!pcap_run_capture(pcap_handle)) {
            fprintf(stderr, "Packet capture stopped due to error.\n");
            goto err_pcap;
        }
    }

    if (interrupted_flag) {
        printf("\nCtrl+C detected, performing cleanup...\n");
    }

err_pcap:
    pcap_uninit(pcap_handle);
    close_log_file("log.txt");
err_cleanup:
    ret = EXIT_FAILURE;
    printf("Resources released. Exiting.\n");
    return ret;
}
