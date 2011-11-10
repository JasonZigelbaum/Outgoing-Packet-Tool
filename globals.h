#ifndef GLOBALS_H
#define GLOBALS_H

#include <string>

extern const bool DEBUG;
extern int term_flag;
extern std::string input;

/* <<< User's IP Address >>> */

extern char* ip_address;

/* <<< Packet Capture Handle >>> */

extern pcap_t *handle;
extern int num_packets;
extern struct bpf_program fp;          /* compiled filter program (expression) */



#endif
