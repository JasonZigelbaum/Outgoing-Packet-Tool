/*
 *
 *functions.h
 *
 */

#include "definitions.h"

#ifndef libpcapTest_functions_h
#define libpcapTest_functions_h

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_usage(void);
void get_packets(void);

/* <<< print help text >>> */

void print_app_usage(void) {
    
    printf("Usage: packet_sniffer [interface]\n");
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");
    
    return;
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

/*
 * dissect/print packet
 */
void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *packet) {
    
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
    
    // Reverse DNS lookup to print out names
    struct sockaddr_in a; 
    int error = 0; 
    char hostname[NI_MAXHOST]; 
    
    memset((void*)&a, 0 , sizeof(a)); 
    a.sin_family = AF_INET; 
    
    if(inet_aton(inet_ntoa(ip->ip_dst), 
                 &(a.sin_addr)) == 0) 
    { 
        std::cout <<"inet_aton returned zero." << std::endl; 
        return; 
    } 
    
    if((error = getnameinfo((struct sockaddr*)&a, sizeof(struct 
                                                         sockaddr), 
                            hostname, sizeof(hostname), NULL,0,
                            NI_NAMEREQD))) 
    { 
        
        std::cout <<"getnameinfo returned error." << std::endl; 
    } 
    
    std::cout <<"Hostname obtained is " <<hostname << std::endl; 
    
    
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
    
    /*
     *  OK, this packet is TCP.
     */
    
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
    
    return;
}

void get_packets(void) {
    
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */
    
    char filter_exp[] = "ip";       /* filter expression [3] */
    struct bpf_program fp;          /* compiled filter program (expression) */
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = 100;          /* number of packets to capture */
    
    
    /* check for capture device name on command-line */
    if (!dev) {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
        std::cout << "Device chosen: " << dev << std::endl;
        
    }
    
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }
    
    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);
    
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
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);
    
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    
    printf("\nCapture complete.\n");
}

#endif
