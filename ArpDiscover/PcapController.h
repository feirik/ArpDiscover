#pragma once

#include "Prober.h"

#include "pcap.h"
#include <stdio.h>
#include <winsock.h>

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

	void InitCapture();
	void CapturePackets();

	int FindActiveInterfaces();

private:
	std::vector<captureData>* m_targetDataPtr;

	int     m_selectedDevNum = -1;
	pcap_t *m_selectedDevHandle;
};

