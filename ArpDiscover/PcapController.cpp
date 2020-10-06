#include "PcapController.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <iostream>
#include <stdexcept>

#include "PcapCallback.h"

PcapController::PcapController(std::vector<captureData>* data)
{
	m_targetDataPtr = data;

	FindActiveInterfaces();

	printf("Found interface %i to scan\n", m_selectedDevNum);

	//CapturePackets();
}


PcapController::~PcapController()
{
}

void PcapController::CapturePackets()
{
	bpf_u_int32 netaddr = 0;
	bpf_u_int32	netmask = 0;
	pcap_if_t   *dev;
	pcap_if_t   *devList;
	pcap_addr_t *devAddr;
	pcap_t      *devHandle;

	struct bpf_program fcode;

	char source[] = PCAP_SRC_IF_STRING;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter[] = "arp";

	int devCount = 0;
	int devLookup = 0;
	int devNum;

	if (pcap_findalldevs_ex(source, NULL, &devList, errbuf) == -1)
	{
		printf("There is a problem with pcap_findalldevs: %s line: %i in %s", errbuf, __LINE__, __func__);
		throw std::runtime_error("pcap_findalldevs failed");
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
				printf("[%i] Found a device %s on address %s with netmask %s\n", devCount, dev->description,
					iptos(((struct sockaddr_in *)devAddr->addr)->sin_addr.s_addr),
					iptos(((struct sockaddr_in *)devAddr->netmask)->sin_addr.s_addr));
			}

			// Print all devices
			//printf("[%i] Found a device %s on address %s with netmask %s\n", devCount, dev->name, iptos(((struct sockaddr_in *)devAddr->addr)->sin_addr.s_addr), iptos(((struct sockaddr_in *)devAddr->netmask)->sin_addr.s_addr));

			++devCount;
		}
	}
	if (devCount == 0)
	{
		throw std::runtime_error("Found no devices through pcap");
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

	if ((devHandle = pcap_open_live(dev->name, MAX_BYTES_TO_CAPTURE, 0, 512, errbuf)) == NULL)
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

	//pcap_loop(devHandle, 0, packet_handler_arp, NULL);

	int ret = 0;

	for (int i = 0; i < 10; ++i)
	{
		ret = pcap_dispatch(devHandle, -1, packet_handler_arp, NULL);
	}

	printf("Dispatch return: %i\n", ret);

	int statSize;

	pcap_stat* stats = pcap_stats_ex(devHandle, &statSize);

	printf("ps_recv: %u ps_drop: %u ps_ifdrop: %u bs_capt: %u\n", stats->ps_recv, stats->ps_drop, stats->ps_ifdrop, stats->ps_capt);

	printf("After packet loop\n");
}

int PcapController::FindActiveInterfaces()
{
	bpf_u_int32 netaddr = 0;
	bpf_u_int32	netmask = 0;

	pcap_if_t   *dev;
	pcap_if_t   *devList;
	pcap_addr_t *devAddr;
	pcap_t      *devHandle;

	struct bpf_program fcode;

	char source[] = PCAP_SRC_IF_STRING;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter[] = "arp";

	int devCount = 0;
	int devLookup = 0;

	const int		 NUMBER_OF_CAPTURE_BUFFER_CYCLES = 10;
	unsigned int     numberOfPacketsCaptured = 0;
	std::vector<int> activeDevPositions;

	// Populate devList with potential devices
	if (pcap_findalldevs_ex(source, NULL, &devList, errbuf) == -1)
	{
		printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
		throw std::runtime_error("pcap_findalldevs failed");
	}

	// Loop through devices
	for (dev = devList; dev != NULL; dev = dev->next)
	{
		// Look through possible mulitple addresses devices might have
		for (devAddr = dev->addresses; devAddr != NULL; devAddr = devAddr->next)
		{
			// Filter for non-zero address, netmask and sa_family
			if (devAddr->addr->sa_family == AF_INET && devAddr->addr && devAddr->netmask)
			{
				activeDevPositions.push_back(devCount);
			}
			++devCount;
		}
	}

	for (unsigned int i = 0; i < activeDevPositions.size(); ++i)
	{
		printf("Dev: %i \n", activeDevPositions.at(i));
	}

	if (activeDevPositions.size() == 0)
	{
		throw std::runtime_error("Found no devices through pcap");
	}

	// Looping through all the potential active devs
	for (unsigned int i = 0; i < activeDevPositions.size(); ++i)
	{
		// Select a device
		int devSearchNum = activeDevPositions.at(i);
		devLookup = 0;

		printf("Selected device %i\n", devSearchNum);

		bool breakFlag = 0;

		// Iterating dev to potential device, dev->next necessary
		for (dev = devList; dev != NULL; dev = dev->next)
		{
			for (devAddr = dev->addresses; devAddr != NULL; devAddr = devAddr->next)
			{
				// Iterated to potential device
				if (devLookup == devSearchNum)
				{
					printf("[%i] Checking traffic for %s on address %s with netmask %s\n", devLookup, dev->description,
						iptos(((struct sockaddr_in *)devAddr->addr)->sin_addr.s_addr),
						iptos(((struct sockaddr_in *)devAddr->netmask)->sin_addr.s_addr));

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

		// Get packet capture descriptor handle
		if ((devHandle = pcap_open_live(dev->name, MAX_BYTES_TO_CAPTURE, 0, 512, errbuf)) == NULL)
		{
			printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
			throw std::runtime_error("pcap_open_live failed");
		}

		// Get subnet and netmask
		if (pcap_lookupnet(dev->name, &netaddr, &netmask, errbuf) == -1)
		{
			printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
			throw std::runtime_error("pcap_lookupnet failed");
		}

		// Compile arp filter
		if (pcap_compile(devHandle, &fcode, filter, 1, netmask) == -1)
		{
			printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
			throw std::runtime_error("pcap_compile failed");
		}

		// Apply filter to device handle
		if (pcap_setfilter(devHandle, &fcode) == -1)
		{
			printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
			throw std::runtime_error("pcap_setfilter failed");
		}

		int statSize;

		// Capturing packets to check if device is receiving packet traffic
		for (int j = 0; j < NUMBER_OF_CAPTURE_BUFFER_CYCLES; ++j)
		{
			pcap_dispatch(devHandle, -1, packet_handler_arp, NULL);
		}

		// Checking packet capture statistics for device
		pcap_stat* stats = pcap_stats_ex(devHandle, &statSize);

		printf("ps_recv: %u ps_drop: %u ps_ifdrop: %u bs_capt: %u\n", stats->ps_recv, stats->ps_drop, stats->ps_ifdrop, stats->ps_capt);

		// If filtered arp captures have been captured, select the interface
		if (stats->ps_capt > 0)
		{
			m_selectedDevNum = devSearchNum;
			break;
		}
		else
		{
			// Store the interface which has captured the most packets
			if (stats->ps_recv > numberOfPacketsCaptured)
			{
				m_selectedDevNum = devSearchNum;
			}
		}
	}

	pcap_freealldevs(devList);

	return 0;
}
