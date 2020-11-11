#pragma once

#include "pcap.h"
#include <stdio.h>
#include <winsock.h>

#pragma comment(lib, "Ws2_32.lib")

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_BYTES_TO_CAPTURE 4096

#define IPTOSBUFFERS 12

#define ETHERNET_HW_TYPE 1
#define IPV4_ADDR 0x0800

#define MAC_SIZE 18
#define IP_SIZE 15

// Ethernet header size
#define H_ETH 14

struct pcapPacketData
{
	char macSenderA[MAC_SIZE] = { 0, };
	char ipSenderA [IP_SIZE]  = { 0, };
	char macTargetA[MAC_SIZE] = { 0, };
	char ipTargetA [IP_SIZE]  = { 0, };
	bool operationIsReplyA    = false;

	char macSenderB[MAC_SIZE] = { 0, };
	char ipSenderB [IP_SIZE]  = { 0, };
	char macTargetB[MAC_SIZE] = { 0, };
	char ipTargetB [IP_SIZE]  = { 0, };
	bool operationIsReplyB    = false;
};

typedef struct arphdr {
	u_int16_t hwType;			 /* Hardware Type           */
	u_int16_t protocolType;      /* Protocol Type           */
	u_char hwAddrLen;            /* Hardware Address Length */
	u_char protocolAddrLen;      /* Protocol Address Length */
	u_int16_t operationCode;     /* Operation Code          */
	u_char macSender[6];		 /* Sender MAC address      */
	u_char ipSender [4];		 /* Sender IP address       */
	u_char macTarget[6];         /* Target MAC address		*/
	u_char ipTarget [4];		 /* Target IP address       */
}arphdr_t;

char *iptos(u_long in);

void packet_handler_arp(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

