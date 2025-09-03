#ifndef PR_PCAP_H
#define PR_PCAP_H
#include <netinet/in.h>
#include <pcap.h>
#include <stdbool.h>
typedef struct {
	unsigned char src_mac[6];
	unsigned char dest_mac[6];
	int length;
	u_int16_t ethertype;
} ethernet_info_t;

typedef struct {
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	int is_ipv6;
	unsigned char protocol;
} ip_info_t;

typedef struct {
	u_int16_t src_port;
	u_int16_t dst_port;
} udp_info_t;

typedef struct {
	uint8_t message_flags;
	uint16_t session_id;
	uint8_t security_flags;
	uint32_t message_counter;
	uint8_t has_source_node_id;
	uint8_t has_destination_node_id;
	uint64_t source_node_id;
	uint64_t destination_node_id;
	uint8_t protocol_opcode;
} matter_info_t;

typedef struct {
	ethernet_info_t eth;
	ip_info_t ip;
	udp_info_t udp;
	matter_info_t matter;
} packet_info_t;

typedef enum {
	PCAP_SOURCE_INTERFACE,
	PCAP_SOURCE_FILE
} pcap_source_t;

typedef struct {
	pcap_t *handle;
	struct bpf_program fp;
	time_t window_start_time;
} pr_pcap_ctx_t;

pr_pcap_ctx_t *pcap_initialize(const char *name, pcap_source_t source_type);
void pcap_uninit(pr_pcap_ctx_t *ctx);
bool pcap_run_capture(pr_pcap_ctx_t *ctx);
#endif // PR_PCAP_H
