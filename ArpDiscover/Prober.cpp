#include "Prober.h"
#include "Oui.h"

#include "PcapController.h"

#include <iomanip>
#include <iostream>

Prober::Prober(userInput inputs) : m_inputs(inputs)
{
	const int TARGET_DATA_START_CAPACITY = 8;

	m_targetData.reserve(TARGET_DATA_START_CAPACITY);

	//std::cout << "Passive: " << inputs.passiveFlag << " Interface: " << inputs.interfaceIn << std::endl;

	PcapController controller(&m_targetData);

	for (int i = 0; i < 10; ++i)
	{
		controller.capturePackets();

		if (controller.getIsEntryAdded() == true)
		{
			printEntries();
		}
	}

	std::cout << "End of scan:" << std::endl;
	printEntries();

	while (1);
}


Prober::~Prober()
{
}

void Prober::printEntries()
{
	std::cout << "Printing vector:" << " size: " << m_targetData.size() << std::endl;

	std::cout << std::left << std::setw(15) << "IP" <<
		" * " << std::setw(17) << "MAC" <<
		" * " << std::setw(26) << "Vendor" << std::setw(18) <<
		" Gratious/Sender/Target" << std::endl;


	for (size_t i = 0; i < m_targetData.size(); ++i)
	{
		std::cout << std::left << std::setw(15) << m_targetData.at(i).ip << 
			" - " << std::setw(17) << m_targetData.at(i).MAC <<
			" - " << std::setw(26) << oui::GetVendor(m_targetData.at(i).MAC) << std::setw(6) <<
			" Grt: " << m_targetData.at(i).arpEvent.gratious <<
		  "   Snd: " << m_targetData.at(i).arpEvent.sender <<
			" Tar: " << m_targetData.at(i).arpEvent.target << std::endl;
	}
}
