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
  iter = normal_hosts_.find(host);
  if (iter != normal_hosts_.end()) {
    return true;
  }
  suspects_.push_back(host);
  return false;
}

void PacketSieve::print_suspects() {
  std::cout << "Possible target hosts (be patient for reverse DNS): "
            << std::endl;
  for (unsigned int i = 0; i < suspects_.size(); ++i) {
    std::cout << "\t" << suspects_[i] << reverse_dns(suspects_[i]);
  }
}

string PacketSieve::reverse_dns(std::string ip) {
 // Print out names
  struct sockaddr_in a; 
  int error = 0; 
  char hostname[NI_MAXHOST]; 
  memset((void*)&a, 0 , sizeof(a)); 
  a.sin_family = AF_INET; 
  if(inet_aton(ip.c_str(), 
  	       &(a.sin_addr)) == 0) 
    { 
      return "N/A"; 
    } 
  if((error = getnameinfo((struct sockaddr*)&a, sizeof(struct 
  						       sockaddr), 
  			  hostname, sizeof(hostname), NULL,0,
  			  NI_NAMEREQD))) 
    { 
      return "N/A";
    } 
  return hostname;
}
