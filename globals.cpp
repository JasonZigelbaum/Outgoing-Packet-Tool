#include <string>
#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <map>
#include <ifaddrs.h>

const bool DEBUG = false;
const int term_flag = 0;
std::string input;

/* <<< User's IP Address >>> */

char ip_address[INET_ADDRSTRLEN];

/* <<< Packet Capture Handle >>> */

int num_packets = 100;
struct bpf_program fp;          /* compiled filter program (expression) */

std::string HOSTS_FILE = "./hosts";