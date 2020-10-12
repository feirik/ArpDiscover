#pragma once

#include "pcap.h"
#include <stdio.h>
#include <winsock.h>

#pragma comment(lib, "Ws2_32.lib")

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_BYTES_TO_CAPTURE 4096

#define IPTOSBUFFERS 12

#define HW_MAXDESC 10
#define PROTOCOL_MAXDESC 11
#define OPERATION_MAXDESC 13
#define TIME_MAXDESC 20

// Ethernet header size
#define H_ETH 14

struct pcapPacketData
{
	char ip[20];
	char MAC[20];
	char vendor[40];
};

typedef struct arphdr {
	u_int16_t hwType;			 /* Hardware Type           */
	u_int16_t protocolType;      /* Protocol Type           */
	u_char hwAddrLen;            /* Hardware Address Length */
	u_char protocolAddrLen;      /* Protocol Address Length */
	u_int16_t operationCode;     /* Operation Code          */
	u_char hwAddrSender[6];      /* Sender hardware address */
	u_char ipAddrSender[4];      /* Sender IP address       */
	u_char hwAddrTarget[6];      /* Target hardware address */
	u_char ipAddrTarget[4];      /* Target IP address       */
}arphdr_t;

char *iptos(u_long in);

void packet_handler_arp(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

