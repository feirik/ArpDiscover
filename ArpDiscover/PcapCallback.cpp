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
	char hw		  [HW_MAXDESC]		  = { 0, };
	char protocol [PROTOCOL_MAXDESC]  = { 0, };
	char operation[OPERATION_MAXDESC] = { 0, };

	// Time data
	struct tm ltime;
	char timestr[TIME_MAXDESC] = { 0, };
	time_t local_tv_sec;

	// Arp header
	arphdr_t *arph;

	// convert the timestamp to readable format
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	arph = (struct arphdr *)(pkt_data + H_ETH);

	if (ntohs(arph->hwType) == 1)
	{
		strncpy_s(hw, "Ethernet", sizeof("Ethernet"));
	}
	else
	{
		strncpy_s(hw, "Unknown", sizeof("Unknown"));
	}

	if (ntohs(arph->protocolType) == 0x0800)
	{
		strncpy_s(protocol, "IPv4", sizeof("IPv4"));
	}
	else
	{
		strncpy_s(protocol, "Unknown", sizeof("Unknown"));
	}

	if (ntohs(arph->operationCode) == ARP_REQUEST)
	{
		strncpy_s(operation, "ARP Request", sizeof("ARP Request"));
	}
	else
	{
		strncpy_s(operation, "ARP Reply", sizeof("ARP Reply"));
	}

	printf("[ARP %i] %s,%.6d len:%d - ", i++, timestr, header->ts.tv_usec, header->len);

	//printf("%s - %s - %s", hw, protocol, operation);

	printf("%s", operation);

	if (ntohs(arph->hwType) == 1 && ntohs(arph->protocolType) == 0x0800)
	{
		printf(" Source MAC: ");

		for (int j = 0; j < 6; ++j)
		{
			printf("%02X", arph->hwAddrSender[j]);
			if (j < 5)
			{
				printf(":");
			}
		}

		printf(" IP: ");

		for (int j = 0; j < 4; ++j)
		{
			printf("%d", arph->ipAddrSender[j]);
			if (j < 3)
			{
				printf(".");
			}
		}

		printf(" Target MAC: ");

		for (int j = 0; j < 6; ++j)
		{
			printf("%02X", arph->hwAddrTarget[j]);
			if (j < 5)
			{
				printf(":");
			}
		}

		printf(" IP: ");

		for (int j = 0; j < 4; ++j)
		{
			printf("%d", arph->ipAddrTarget[j]);
			if (j < 3)
			{
				printf(".");
			}
		}

		printf("\n");
	}

	pcapPacketData* testData = (pcapPacketData*)param;

	strncpy_s(testData->ip, "IpTest", sizeof("IpTest"));
}