#pragma once

#include "pcap.h"
#include <stdio.h>
#include <winsock.h>

#pragma comment(lib, "Ws2_32.lib")

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_BYTES_TO_CAPTURE 4096

#define IPTOSBUFFERS 12

#define MAX_HW_DESC_SIZE 10
#define MAX_PROTOCOL_DESC_SIZE 11
#define MAX_OPERATION_DESC_SIZE 13
#define MAX_TIME_DESC_SIZE 20

// Ethernet header size
#define H_ETH 14

struct pcapPacketData
{
	char macSender[20] = { 0, };
	char ipSender[15] = { 0, };
	char macTarget[20] = { 0, };
	char ipTarget[15] = { 0, };
	bool operationIsReply = false;
};

typedef struct arphdr {
	u_int16_t hwType;			 /* Hardware Type           */
	u_int16_t protocolType;      /* Protocol Type           */
	u_char hwAddrLen;            /* Hardware Address Length */
	u_char protocolAddrLen;      /* Protocol Address Length */
	u_int16_t operationCode;     /* Operation Code          */
	u_char macSender[6];		 /* Sender MAC address      */
	u_char ipSender[4];			 /* Sender IP address       */
	u_char macTarget[6];         /* Target MAC address		*/
	u_char ipTarget[4];			 /* Target IP address       */
}arphdr_t;

char *iptos(u_long in);

void packet_handler_arp(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

