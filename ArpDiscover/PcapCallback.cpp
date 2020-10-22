#include "PcapCallback.h"

#include <string.h>

/* From tcptraceroute, convert a numeric IP address to a string */
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

// Callback function invoked by libpcap for every incoming packet
void packet_handler_arp(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	// Static package count
	static int i = 0;

	// Time data
	struct tm ltime;
	char timestr[MAX_TIME_DESC_SIZE] = { 0, };
	time_t local_tv_sec;

	// Arp header
	arphdr_t *arph;

	// Getting struct pointer from argument passed in PcapController
	pcapPacketData* packetData = (pcapPacketData*)param;

	// convert the timestamp to readable format
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	arph = (struct arphdr *)(pkt_data + H_ETH);

	if (ntohs(arph->hwType) == ETHERNET_HW_TYPE && ntohs(arph->protocolType) == IPV4_ADDR)
	{
		// A/B packetData split - Check that A-data has not been populated
		if (packetData->ipSenderA[0] == 0)
		{
			snprintf(packetData->ipSenderA, IP_SIZE, "%u.%u.%u.%u",
				arph->ipSender[0], arph->ipSender[1], arph->ipSender[2], arph->ipSender[3]);

			snprintf(packetData->ipTargetA, IP_SIZE, "%u.%u.%u.%u",
				arph->ipTarget[0], arph->ipTarget[1], arph->ipTarget[2], arph->ipTarget[3]);

			snprintf(packetData->macSenderA, MAC_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
				arph->macSender[0], arph->macSender[1], arph->macSender[2],
				arph->macSender[3], arph->macSender[4], arph->macSender[5]);

			snprintf(packetData->macTargetA, MAC_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
				arph->macTarget[0], arph->macTarget[1], arph->macTarget[2],
				arph->macTarget[3], arph->macTarget[4], arph->macTarget[5]);

			if (ntohs(arph->operationCode) == ARP_REPLY)
			{
				packetData->operationIsReplyA = true;
			}
			else
			{
				packetData->operationIsReplyA = false;
			}
		}
		// If A-data is populated, store in B-data instead
		else
		{
			snprintf(packetData->ipSenderB, IP_SIZE, "%u.%u.%u.%u",
				arph->ipSender[0], arph->ipSender[1], arph->ipSender[2], arph->ipSender[3]);

			snprintf(packetData->ipTargetB, IP_SIZE, "%u.%u.%u.%u",
				arph->ipTarget[0], arph->ipTarget[1], arph->ipTarget[2], arph->ipTarget[3]);

			snprintf(packetData->macSenderB, MAC_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
				arph->macSender[0], arph->macSender[1], arph->macSender[2],
				arph->macSender[3], arph->macSender[4], arph->macSender[5]);

			snprintf(packetData->macTargetB, MAC_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
				arph->macTarget[0], arph->macTarget[1], arph->macTarget[2],
				arph->macTarget[3], arph->macTarget[4], arph->macTarget[5]);

			if (ntohs(arph->operationCode) == ARP_REPLY)
			{
				packetData->operationIsReplyB = true;
			}
			else
			{
				packetData->operationIsReplyB = false;
			}
		}
	}
}