#include "PcapController.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <iostream>
#include <stdexcept>

PcapController::PcapController(std::vector<captureData>* data)
	: m_targetDataPtr(data)
{
	findActiveInterfaces();

	initCapture();
}


PcapController::~PcapController()
{
}

int PcapController::findActiveInterfaces()
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

	// Throw exception if no potential devices were found
	if (activeDevPositions.size() == 0)
	{
		throw std::runtime_error("Found no devices through pcap");
	}

	printf("Finding active interface - Scanning: ");

	// Looping through all the potential active devs
	for (size_t i = 0; i < activeDevPositions.size(); ++i)
	{
		// Select a device
		int devSearchNum = activeDevPositions.at(i);
		devLookup = 0;

		bool breakFlag = 0;
		
		// Iterating dev to potential device, dev->next necessary
		for (dev = devList; dev != NULL; dev = dev->next)
		{
			for (devAddr = dev->addresses; devAddr != NULL; devAddr = devAddr->next)
			{
				// Iterated to potential device
				if (devLookup == devSearchNum)
				{
					printf("%s", iptos(((struct sockaddr_in *)devAddr->addr)->sin_addr.s_addr));

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
			pcap_dispatch(devHandle, -1, packet_handler_arp, (u_char*)&m_packetData);
			printf(".");
		}

		// Checking packet capture statistics for device
		pcap_stat* stats = pcap_stats_ex(devHandle, &statSize);

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
	return 0;
}

void PcapController::initCapture()
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

	int  devLookup = 0;
	bool breakFlag = 0;

	printf("\nPacket capture - Selected device %i\n", m_selectedDevNum);

	// Populate devList with potential devices
	if (pcap_findalldevs_ex(source, NULL, &devList, errbuf) == -1)
	{
		printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
		throw std::runtime_error("pcap_findalldevs failed");
	}

	// Iterating dev to potential device, dev->next necessary
	for (dev = devList; dev != NULL; dev = dev->next)
	{
		for (devAddr = dev->addresses; devAddr != NULL; devAddr = devAddr->next)
		{
			// Iterated to potential device
			if (devLookup == m_selectedDevNum)
			{
				printf("Capturing traffic on %s with netmask %s\n",
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
	else
	{
		m_selectedDevHandle = devHandle;
	}

	// Get subnet and netmask
	if (pcap_lookupnet(dev->name, &netaddr, &netmask, errbuf) == -1)
	{
		printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
		throw std::runtime_error("pcap_lookupnet failed");
	}

	// Compile arp filter
	if (pcap_compile(m_selectedDevHandle, &fcode, filter, 1, netmask) == -1)
	{
		printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
		throw std::runtime_error("pcap_compile failed");
	}

	// Apply filter to device handle
	if (pcap_setfilter(m_selectedDevHandle, &fcode) == -1)
	{
		printf("ERROR: %s line: %i in %s", errbuf, __LINE__, __func__);
		throw std::runtime_error("pcap_setfilter failed");
	}

	pcap_freealldevs(devList);
}

void PcapController::capturePackets()
{
	const int NUMBER_OF_CAPTURE_BUFFER_CYCLES = 10;
	int       ret = 0;

	setIsEntryAdded(false);

	for (int i = 0; i < NUMBER_OF_CAPTURE_BUFFER_CYCLES; ++i)
	{
		ret = pcap_dispatch(m_selectedDevHandle, -1, packet_handler_arp, (u_char*) &m_packetData);

		if (ret > 0)
		{
			convertPacketDataToCppString();

			manageEntries(m_packetDataCppA);

			// If B-data has been captured, also analyse it
			if (m_packetDataCppB.ipSender.size() != 0)
			{
				manageEntries(m_packetDataCppB);
			}

			clearPacketData();
		}
	}
}

void PcapController::convertPacketDataToCppString()
{
	m_packetDataCppA.ipSender		 = m_packetData.ipSenderA;
	m_packetDataCppA.ipTarget		 = m_packetData.ipTargetA;
	m_packetDataCppA.macSender		 = m_packetData.macSenderA;
	m_packetDataCppA.macTarget		 = m_packetData.macTargetA;
	m_packetDataCppA.operationIsReply = m_packetData.operationIsReplyA;

	// If data was populated in B-data (pcap_dispatch returned 2 packets), store data
	if (m_packetData.ipSenderB[0] != 0)
	{
		m_packetDataCppB.ipSender = m_packetData.ipSenderB;
		m_packetDataCppB.ipTarget = m_packetData.ipTargetB;
		m_packetDataCppB.macSender = m_packetData.macSenderB;
		m_packetDataCppB.macTarget = m_packetData.macTargetB;
		m_packetDataCppB.operationIsReply = m_packetData.operationIsReplyB;
	}
}

void PcapController::clearPacketData()
{
	memset(m_packetData.ipSenderA,  0, IP_SIZE);
	memset(m_packetData.ipTargetA,  0, IP_SIZE);
	memset(m_packetData.macSenderA, 0, MAC_SIZE);
	memset(m_packetData.macTargetA, 0, MAC_SIZE);
	m_packetData.operationIsReplyA = false;

	memset(m_packetData.ipSenderB, 0, IP_SIZE);
	memset(m_packetData.ipTargetB, 0, IP_SIZE);
	memset(m_packetData.macSenderB, 0, MAC_SIZE);
	memset(m_packetData.macTargetB, 0, MAC_SIZE);
	m_packetData.operationIsReplyB = false;

	m_packetDataCppA.ipSender = "";
	m_packetDataCppA.ipTarget = "";
	m_packetDataCppA.macSender = "";
	m_packetDataCppA.macTarget = "";
	m_packetDataCppA.operationIsReply = false;

	m_packetDataCppB.ipSender = "";
	m_packetDataCppB.ipTarget = "";
	m_packetDataCppB.macSender = "";
	m_packetDataCppB.macTarget = "";
	m_packetDataCppB.operationIsReply = false;
}

void PcapController::manageEntries(const packetDataAsCppString& packetData)
{
	bool isSenderStored = false;
	bool isTargetStored = false;

	// Checking if sender is stored
	for (size_t i = 0; i < m_targetDataPtr->size(); ++i)
	{
		if (m_targetDataPtr->at(i).ip == packetData.ipSender)
		{
			isSenderStored = true;

			// Update MAC if it was originally set to broadcast MAC
			if ((m_targetDataPtr->at(i).MAC == MAC_ADDRESS_ALL_ZEROES) &&
				(packetData.macSender != MAC_ADDRESS_ALL_ZEROES))
			{
				m_targetDataPtr->at(i).MAC = packetData.macSender;
			}
			break;
		}
	}
	if (isSenderStored == false)
	{
		addEntry(packetData, EntryType::sender);
	}

	// Checking if target is stored
	for (size_t i = 0; i < m_targetDataPtr->size(); ++i)
	{
		if (m_targetDataPtr->at(i).ip == packetData.ipTarget)
		{
			isTargetStored = true;

			// Update MAC if it was originally set to broadcast MAC
			if ((m_targetDataPtr->at(i).MAC == MAC_ADDRESS_ALL_ZEROES) &&
				(packetData.macSender != MAC_ADDRESS_ALL_ZEROES))
			{
				m_targetDataPtr->at(i).MAC = packetData.macTarget;
			}
			break;
		}
	}
	if (isTargetStored == false)
	{
		addEntry(packetData, EntryType::target);
	}
	// If both sender and target are stored, setting arp event flags
	if (isSenderStored == true && isTargetStored == true)
	{
		for (size_t i = 0; i < m_targetDataPtr->size(); ++i)
		{
			// First check if packet was a gratious ARP packet
			if ((m_targetDataPtr->at(i).ip == packetData.ipSender)
				&& (packetData.ipSender == packetData.ipTarget)
				&& (packetData.macTarget == MAC_ADDRESS_ALL_ZEROES))
			{
					m_targetDataPtr->at(i).arpEvent.gratious = true;
			}
			// Or if the IP data entry is an arp sender
			else if (m_targetDataPtr->at(i).ip == packetData.ipSender)
			{
					m_targetDataPtr->at(i).arpEvent.sender = true;
			}
			// Or if the IP data entry is an arp target
			else if (m_targetDataPtr->at(i).ip == packetData.ipTarget)
			{
					m_targetDataPtr->at(i).arpEvent.target = true;
			}
		}
	}
}

void PcapController::addEntry(const packetDataAsCppString& packetData, EntryType entryType)
{
	captureData newEntry;

	// First check if packet was a gratious ARP packet
	if ((packetData.ipSender == packetData.ipTarget) &&
	    (packetData.macTarget == MAC_ADDRESS_ALL_ZEROES))
	{
		newEntry.arpEvent.gratious = true;
		newEntry.ip = packetData.ipSender;
		newEntry.MAC = packetData.macSender;
	}
	else
	{
		if (entryType == EntryType::sender)
		{
			newEntry.ip = packetData.ipSender;
			newEntry.MAC = packetData.macSender;
			newEntry.arpEvent.sender = true;
		}
		else
		{
			newEntry.ip = packetData.ipTarget;
			newEntry.MAC = packetData.macTarget;
			newEntry.arpEvent.target = true;
		}
	}

	m_targetDataPtr->emplace_back(newEntry);
	setIsEntryAdded(true);
}






