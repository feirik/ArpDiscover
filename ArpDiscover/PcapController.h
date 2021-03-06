#pragma once

#include "Prober.h"
#include "Misc.h"

#include "pcap.h"
#include <stdio.h>
#include <winsock.h>

#include "PcapCallback.h"

#define MAC_ADDRESS_ALL_ZEROES "00:00:00:00:00:00"

enum EntryType {
	sender = 0,
	target
};

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
	PcapController(std::vector<captureData>* data, const userInput& input);
	~PcapController();

	void initCapture();
	void capturePackets();

	int findActiveInterfaces();

	void convertPacketDataToCppString();

	void clearPacketData();

	void manageEntries(const packetDataAsCppString& packetData);
	void addEntry(const packetDataAsCppString& packetData, EntryType type);

	bool getIsEntryAdded() const				  { return m_isEntryAdded; }
	void setIsEntryAdded(const bool isEntryAdded) { m_isEntryAdded = isEntryAdded; }

	bool isInterfaceSet() const;

private:
	std::vector<captureData>* m_targetDataPtr;
	userInput m_inputPtr;

	pcapPacketData m_packetData;

	packetDataAsCppString m_packetDataCppA;
	packetDataAsCppString m_packetDataCppB;

	int     m_selectedDevNum = -1;
	pcap_t *m_selectedDevHandle;
	bool    m_isEntryAdded;
};

