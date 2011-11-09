#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "definitions.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void handle_target_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_usage(void);
void fill_packet_sieve(void);
void get_ip(void);
void get_handle(void);
void term_sniffer(void);
void select_packets(void);

#endif
