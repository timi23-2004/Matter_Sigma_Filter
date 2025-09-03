SOURCES = pr_task.c pr_pcap.c pr_print.c pr_clean.c pr_log.c pr_sig1_case.c

.PHONY: all
all: pr_task

pr_task: $(SOURCES)
	$(CC) $(SOURCES) -Wall -pedantic -lpcap -o matter_sigma_filter

.PHONY: clean
clean:
	rm -rf pr_task
