#include <string>
#include <vector>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>

#include "packet-sieve.h"

using namespace std;

bool PacketSieve::check_host(std::string host) {
  AddressMap::iterator iter = normal_hosts_.begin();
  // Look up host in known hosts map
  iter = normal_hosts_.find(host);
  if (iter != normal_hosts_.end()) {
    return true;
  }

  // Look up hosts in suspects map
  iter = suspect_hosts_.find(host);
  if (iter != suspect_hosts_.end()) {
    // Increment our count of packets seen.
    iter->second = iter->second + 1;
    return false;
  }
  suspect_hosts_.insert(std::pair<std::string, bool>
			      (host, 1));
  return false;
}

void PacketSieve::print_suspects() {
  std::cout << suspect_hosts_.size()
	    << " possible target hosts (be patient for reverse DNS): "
            << std::endl;

  AddressMap::iterator iter;
  for (iter = suspect_hosts_.begin(); iter != suspect_hosts_.end(); ++iter) {
    std::cout << iter->first << " " << reverse_dns(iter->first)
              << " " << iter->second << std::endl;
  }
}

string PacketSieve::reverse_dns(std::string ip) {
  // Print out names
  struct sockaddr_in a; 
  int error = 0; 
  char hostname[NI_MAXHOST]; 
  memset((void*)&a, 0 , sizeof(a)); 
  a.sin_family = AF_INET; 
  if(inet_aton(ip.c_str(),  &(a.sin_addr)) == 0) { 
    return "N/A"; 
  } 
  if((error = getnameinfo((struct sockaddr*)&a, sizeof(struct 
  						       sockaddr), 
  			  hostname, sizeof(hostname), NULL,0,
  			  NI_NAMEREQD))) { 
    return "Unknown";
  } 
  return hostname;
}
