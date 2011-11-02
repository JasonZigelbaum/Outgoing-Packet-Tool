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
#include "definitions.h"
#include "functions.h"

using namespace std;

int main(int argc, char **argv)
{
    if (argc == 2) {
        dev = argv[1];
    }
    
     printf("Welcome to our packet sniffer!\nYou are sniffing on %s\nPlease type train to train, followed by ass_conn\n", dev);
    
    while(!term_flag){
        printf(">> ");
        cin >> input;
        if (input == "train"){
            cout << "you typed train\n";
        }
        if (input == "ass_conn"){
            cout << "you typed ass_conn";
            get_packets();
        }
    }

    return 0;
}