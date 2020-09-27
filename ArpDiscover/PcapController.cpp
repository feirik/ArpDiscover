#include "PcapController.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <iostream>

#include "PcapCallback.h"

PcapController::PcapController()
{
	bpf_u_int32 netaddr = 0, netmask = 0;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev;
	pcap_if_t *devList;

	pcap_addr_t *devAddr;

	pcap_t *devHandle;

	char source[] = PCAP_SRC_IF_STRING;
	char filter[] = "arp";

	int devCount = 0;
	int devLookup = 0;
	int devNum;

	if (pcap_findalldevs_ex(source, NULL, &devList, errbuf) == -1)
	{
		printf("There is a problem with pcap_findalldevs: %s", errbuf);
		//return -1;
	}

	// Loop through devices
	for (dev = devList; dev != NULL; dev = dev->next)
	{
		// Look through possible mulitple addresses device might have
		for (devAddr = dev->addresses; devAddr != NULL; devAddr = devAddr->next)
		{
			// Filter for non-zero address, netmask and sa_family
			if (devAddr->addr->sa_family == AF_INET && devAddr->addr && devAddr->netmask)
			{
				printf("[%i] Found a device %s on address %s with netmask %s\n", devCount, dev->name, iptos(((struct sockaddr_in *)devAddr->addr)->sin_addr.s_addr), iptos(((struct sockaddr_in *)devAddr->netmask)->sin_addr.s_addr));
			}

			// Print all devices
			//printf("[%i] Found a device %s on address %s with netmask %s\n", devCount, dev->name, iptos(((struct sockaddr_in *)devAddr->addr)->sin_addr.s_addr), iptos(((struct sockaddr_in *)devAddr->netmask)->sin_addr.s_addr));

			++devCount;
		}
	}
	if (devCount == 0)
	{
		printf("\nFound no devices!\n");
		//return -1;
	}

	std::cout << "Choose capture interface number: ";
	std::cin >> devNum;

	std::cout << "You input " << devNum << std::endl;

	// Check if input user number is valid
	if (-1 < devNum && devNum <= devCount)
	{
		bool breakFlag = 0;

		for (dev = devList; dev != NULL; dev = dev->next)
		{
			for (devAddr = dev->addresses; devAddr != NULL; devAddr = devAddr->next)
			{
				// Iterated back to chosen device
				if (devLookup == devNum)
				{
					breakFlag = true;
					break;
				}
				++devLookup;
			}
			// Break out of both for-loops
			if (breakFlag)
			{
				break;
			}
		}
	}
	else
	{
		printf("Error: device number must be a valid device!\n");
		pcap_freealldevs(devList);
		//return -1;
	}

	printf("Capturing %s - %s\n", iptos(((struct sockaddr_in *)devAddr->addr)->sin_addr.s_addr), dev->name);

	if ((devHandle = pcap_open_live(dev->name, MAXBYTES2CAPTURE, 0, 512, errbuf)) == NULL)
	{
		fprintf(stderr, "ERROR: %s\n", errbuf);
		//exit(1);
	}

	// Look up info from the capture device
	if (pcap_lookupnet(dev->name, &netaddr, &netmask, errbuf) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", errbuf);
		//exit(1);
	}

	if (pcap_compile(devHandle, &fcode, filter, 1, netmask) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(devHandle));
		//exit(1);
	}

	if (pcap_setfilter(devHandle, &fcode) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(devHandle));
		//exit(1);
	}

	pcap_freealldevs(devList);

	pcap_loop(devHandle, 0, packet_handler_arp, NULL);
}


PcapController::~PcapController()
{
}
