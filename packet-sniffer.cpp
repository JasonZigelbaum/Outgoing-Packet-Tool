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
#include "packet-sieve.h"

char tmpIpAddress[INET_ADDRSTRLEN];
char* dev;

// Using singleton design pattern.
PacketSniffer* PacketSniffer::instance_ = NULL;

PacketSniffer* PacketSniffer::instance() {
   if (instance_ == NULL) {
      instance_ = new PacketSniffer();
   }
   return instance_;
}


/* <<< Get user's IP address >>> */
void PacketSniffer::get_ip(void) {
  struct ifaddrs * ifAddrStruct=NULL;
  struct ifaddrs * ifa=NULL;
  void * tmpAddrPtr=NULL;
  getifaddrs(&ifAddrStruct);
  for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
  if (ifa ->ifa_addr->sa_family==AF_INET) { // check it is IP4
      // is a valid IP4 Address
      tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
      const char* retval = inet_ntop(AF_INET, tmpAddrPtr, tmpIpAddress, INET_ADDRSTRLEN);
      if (!retval) {
	std::cout << "Error converting numeric address." << std::endl;
      }
      std::cout << "IP Address: " << ifa->ifa_name << " " << tmpIpAddress << std::endl;
    }
  }
  if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);
}

/* <<< print help text >>> */

void PacketSniffer::print_app_usage(void) {
    
  printf("Usage: packet_sniffer [interface]\n");
  printf("\n");
  printf("Options:\n");
  printf("    interface    Listen on <interface> for packets.\n");
  printf("\n");
    
  return;
}

/* <<< Get Handle >>> */

void PacketSniffer::get_handle(void) {
    
  char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    
  bpf_u_int32 mask;           /* subnet mask */
  bpf_u_int32 net;            /* ip */
    
    std::cout << "Dev: " << (void *) dev << std::endl;
  /* check for capture device name on command-line */
 
    // Try default lookup first, then resort to hard-coded secondary option.
    dev = pcap_lookupdev(errbuf);
    bool error = false;
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n",
    	      errbuf);
      error = true;
    }
    if (!error) {
      if( pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		dev, errbuf);
	net = 0;
	mask = 0;
        error = true;
      }
    }
    if (error) {
      string wifi = "wlan0";
      dev = new char[1000];
      strcpy(dev, wifi.c_str());
      std::cout << "Device chosen: " << dev << std::endl;
    if (error) {
      string wifi = "en1";
      dev = new char[1000];
      strcpy(dev, wifi.c_str());
      std::cout << "Device chosen: " << dev << std::endl;
    }
      if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		dev, errbuf);
	net = 0;
	mask = 0;
      }
    }     
    //}
  /* get network number and mask associated with capture device */

  // We only want to capture outgoing packets, so we must find the local
  // IP address for use with a source filter.
  get_ip();
  std::stringstream filter_stream;
  filter_stream << "ip src host ";
  filter_stream << tmpIpAddress;
  filter_stream << " and not udp";
  std::cout << "Local host IP Address is " << filter_stream.str() << std::endl;
    
  /* print capture info */
  printf("Device: %s\n", dev);
  printf("Number of packets: %d\n", num_packets);
  std::cout << "Filter expression: " << filter_stream.str();
    
  /* open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, 0, 10000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }
    
  /* make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }
    
  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_stream.str().c_str(), 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
	    filter_stream.str().c_str(), pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
    
  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
	    filter_stream.str().c_str(), pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
}

/* <<< print data in rows of 16 bytes: offset   hex   ascii
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..>>> */

void print_hex_ascii_line(const u_char *payload, int len, int offset) {
    
  int i;
  int gap;
  const u_char *ch;
    
  /* offset */
  printf("%05d   ", offset);
    
  /* hex */
  ch = payload;
  for(i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    printf(" ");
    
  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");
    
  /* ascii (if printable) */
  ch = payload;
  for(i = 0; i < len; i++) {
    if (isprint(*ch))
      printf("%c", *ch);
    else
      printf(".");
    ch++;
  }
    
  printf("\n");
    
  return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(u_char *payload, int len) {
    
  int len_rem = len;
  int line_width = 16;            /* number of bytes per line */
  int line_len;
  int offset = 0;                 /* zero-based offset counter */
  const u_char *ch = payload;
    
  if (len <= 0)
    return;
    
  /* data fits on one line */
  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }
    
  /* data spans multiple lines */
  for ( ;; ) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    print_hex_ascii_line(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }
    
  return;
}

void handle_target_packet(u_char * args, const struct pcap_pkthdr *,
                          const u_char *packet) {
  PacketSieve* sieve = (PacketSieve*) args;
    
  static int count = 1;                   /* packet counter */
	
  /* declare pointers to packet headers */
  // const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
    
  int size_ip;
  int size_tcp;
	
  count++;
	
  /* define ethernet header */
  // ethernet = (struct sniff_ethernet*)(packet);
	
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
    
  /* determine protocol */	
  switch(ip->ip_p) {
  case IPPROTO_TCP:
    break;
  case IPPROTO_UDP:
    return;
  case IPPROTO_ICMP:
    return;
  case IPPROTO_IP:
    return;
  default:
    return;
  }
	
  /* define/compute tcp header offset */
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }
    
  // Check to see if we have seen this host during our training period.
  // check_host returns true if the host is known, otherwise the host is
  // added to our list of suspects.
  if (sieve->check_host(inet_ntoa(ip->ip_dst))) {
    std::cout << "Ignoring communication with " << inet_ntoa(ip->ip_dst)
	      << std::endl;
  } else {
    std::cout << "CANDIDATE: " << inet_ntoa(ip->ip_dst) << std::endl;
  }
    
  return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char * args, const struct pcap_pkthdr *,
                const u_char *packet) {
  PacketSieve* sieve = (PacketSieve*) args;
    
  static int count = 1;                   /* packet counter */
	
  /* declare pointers to packet headers */
  // const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  u_char *payload;                    /* Packet payload */
    
  int size_ip;
  int size_tcp;
  int size_payload;
	
  printf("\nPacket number %d:\n", count);
  count++;
	
  /* define ethernet header */
  // ethernet = (struct sniff_ethernet*)(packet);
	
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
    
  /* print source and destination IP addresses */
  printf("       From: %s\n", inet_ntoa(ip->ip_src));
  printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    
  /* determine protocol */	
  switch(ip->ip_p) {
  case IPPROTO_TCP:
    printf("   Protocol: TCP\n");
    break;
  case IPPROTO_UDP:
    printf("   Protocol: UDP\n");
    return;
  case IPPROTO_ICMP:
    printf("   Protocol: ICMP\n");
    return;
  case IPPROTO_IP:
    printf("   Protocol: IP\n");
    return;
  default:
    printf("   Protocol: unknown\n");
    return;
  }
	
  /* define/compute tcp header offset */
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }
	
  printf("   Src port: %d\n", ntohs(tcp->th_sport));
  printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
  /* define/compute tcp payload (segment) offset */
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
  /*
   * Print payload data; it might be binary, so don't just
   * treat it as a string.
   */
  if (size_payload > 0) {
    printf("   Payload (%d bytes):\n", size_payload);
    print_payload(payload, size_payload);
  }
    
  // Insert packet into map keyed by destination address.  Later,
  // we will check to see if we've communicated with this host before
  // by checking the map for its address.
  std::cout << "Here." << std::endl;
  sieve->normal_hosts_.insert(std::pair<std::string, bool>
			      (inet_ntoa(ip->ip_dst), 1));
    
  std::cout << "Inserted into sieve." << std::endl;
  return;
    
}

void PacketSniffer::fill_packet_sieve(void) {
    
  get_handle();
    
  /* now we can set our callback function 
     this will also fill our packet sieve for the proceeding loop.
  */
  sieve = new PacketSieve();
  std::cout << "Looping from PacketSieve." << std::endl;
  pcap_loop(handle, 0, got_packet, (u_char*) sieve);
  std::cout << "LOOP BROKEN" << std::endl;
}

void PacketSniffer::select_packets(void) {
    
  // We are done training our packet engine, now lets loop, fire up the
  // target application, and try to find out what is might be.
  if (handle) {
    std::cout << "Looping from select_packets." << std::endl;
    pcap_loop(handle, 0, handle_target_packet, (u_char*) sieve);
    //sieve->print_suspects();
    //term_sniffer();
  } else {
    std::cout << "You need to run train first\n";
  }

}

void PacketSniffer::term_sniffer(void) {
    
  /* cleanup */
  pcap_freecode(&fp);
  pcap_close(handle);
  handle = NULL;
  printf("\nCapture complete.\n");
}
