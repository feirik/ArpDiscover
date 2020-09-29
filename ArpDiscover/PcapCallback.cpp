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
	char hw[HW_MAXDESC];
	char protocol[PROTOCOL_MAXDESC];
	char operation[OPERATION_MAXDESC];

	// Time data
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	// Headers
	arphdr_t *arph;

	// Unused variable
	(VOID)(param);

	// convert the timestamp to readable format
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	arph = (struct arphdr *)(pkt_data + H_ETH);

	if (ntohs(arph->htype) == 1)
	{
		strcpy_s(hw, "Ethernet");
	}
	else
	{
		strcpy_s(hw, "Unknown");
	}

	if (ntohs(arph->ptype) == 0x0800)
	{
		strcpy_s(protocol, "IPv4");
	}
	else
	{
		strcpy_s(protocol, "Unknown");
	}

	if (ntohs(arph->oper) == ARP_REQUEST)
	{
		strcpy_s(operation, "ARP Request");
	}
	else
	{
		strcpy_s(operation, "ARP Reply");
	}

	printf("[ARP %i] %s,%.6d len:%d - ", i++, timestr, header->ts.tv_usec, header->len);

	//printf("%s - %s - %s", hw, protocol, operation);

	printf("%s", operation);

	if (ntohs(arph->htype) == 1 && ntohs(arph->ptype) == 0x0800)
	{
		printf(" Source MAC: ");

		for (int i = 0; i < 6; ++i)
		{
			printf("%02X", arph->sha[i]);
			if (i < 5)
			{
				printf(":");
			}
		}

		printf(" IP: ");

		for (int i = 0; i < 4; ++i)
		{
			printf("%d", arph->spa[i]);
			if (i < 3)
			{
				printf(".");
			}
		}

		printf(" Target MAC: ");

		for (int i = 0; i < 6; ++i)
		{
			printf("%02X", arph->tha[i]);
			if (i < 5)
			{
				printf(":");
			}
		}

		printf(" IP: ");

		for (int i = 0; i < 4; ++i)
		{
			printf("%d", arph->tpa[i]);
			if (i < 3)
			{
				printf(".");
			}
		}

		printf("\n");
	}
}