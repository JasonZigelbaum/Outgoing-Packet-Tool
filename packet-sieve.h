#ifndef PACKET_SIEVE_H
#define PACKET_SIEVE_H

#include <string>
#include <vector>
#include <map>

using namespace std;
#include <netdb.h>

// Map type used to detect unordinary traffic.
typedef std::map<std::string, bool> AddressMap;

class PacketSieve {
public:
  AddressMap normal_hosts_;
  vector<string> suspects_;
  bool check_host(std::string host);

  void print_suspects();
  // Utility function for looking up host names from IP address.
  static std::string reverse_dns(std::string ip);

private:

};


#endif
