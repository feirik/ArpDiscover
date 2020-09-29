#pragma once

#include "pcap.h"
#include <stdio.h>
#include <winsock.h>

#pragma comment(lib, "Ws2_32.lib")

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_BYTES_TO_CAPTURE 4096

#define IPTOSBUFFERS 12

#define HW_MAXDESC 9
#define PROTOCOL_MAXDESC 8
#define OPERATION_MAXDESC 12

// Ethernet header size
#define H_ETH 14

typedef struct arphdr {
	u_int16_t htype;    /* Hardware Type           */
	u_int16_t ptype;    /* Protocol Type           */
	u_char hlen;        /* Hardware Address Length */
	u_char plen;        /* Protocol Address Length */
	u_int16_t oper;     /* Operation Code          */
	u_char sha[6];      /* Sender hardware address */
	u_char spa[4];      /* Sender IP address       */
	u_char tha[6];      /* Target hardware address */
	u_char tpa[4];      /* Target IP address       */
}arphdr_t;

char *iptos(u_long in);

void packet_handler_arp(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

