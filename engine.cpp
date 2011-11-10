/*
 *
 * OUTBOUND PACKET SNIFFER V.1 
 * By : Jonathan Wald & Jason Zigelbaum
 *
 */

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
#include <sstream>
#include <map>
#include <ifaddrs.h>
#include <iterator>
#include "globals.h"
#include "packet-sieve.h"
#include "definitions.h"
#include "packet-sniffer.h"

using namespace std;

int main(int argc, char **argv)
{
  if (argc == 2) {
    //dev = argv[1];
  }
    
  //printf("Welcome to our packet sniffer!\nYou are sniffing on %s\nPlease type train to train, followed by ass_conn\n", dev);
    
  while(true){
    printf(">> ");
    cin >> input;
    if (input == "train"){
      fill_packet_sieve();
    }
    if (input == "ass_conn"){
      select_packets();
    }
	if (input == "quit"){
      term_flag = 1;
    }
  }
    
  return 0;
}
