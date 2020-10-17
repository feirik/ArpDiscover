#pragma once

#include "Prober.h"

#include "pcap.h"
#include <stdio.h>
#include <winsock.h>

#include "PcapCallback.h"

#define MAC_ADDRESS_ALL_ZEROES "00:00:00:00:00:00"

struct packetDataAsCppString
{
	std::string macSender;
	std::string ipSender;
	std::string macTarget;
	std::string ipTarget;
	bool operationIsReply = false;
};

struct pcapDevData
{
	pcap_if_t dev;
	std::vector<pcap_addr_t> addr;
};

class PcapController
{
public:
	PcapController(std::vector<captureData>* m_targetData);
	~PcapController();

	void initCapture();
	void capturePackets();

	int findActiveInterfaces();

	void convertPacketDataToCppString();

	void clearPacketData();

	bool manageStoredEntry(const pcapPacketData& packetData);

private:
	std::vector<captureData>* m_targetDataPtr;

	pcapPacketData m_packetData;

	packetDataAsCppString m_packetDataCpp;

	int     m_selectedDevNum = -1;
	pcap_t *m_selectedDevHandle;
};

