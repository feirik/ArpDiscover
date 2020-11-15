#include "Prober.h"
#include "Oui.h"

#include "PcapController.h"

#include <iomanip>
#include <iostream>

Prober::Prober(userInput inputs) : m_inputs(inputs)
{
	const int TARGET_DATA_START_CAPACITY = 8;
	const int CAPTURE_CYCLE_NUMBER = 10;

	m_targetData.reserve(TARGET_DATA_START_CAPACITY);

	PcapController controller(&m_targetData, m_inputs);

	for (int i = 0; i < CAPTURE_CYCLE_NUMBER; ++i)
	{
		controller.capturePackets();

		if (controller.getIsEntryAdded() == true)
		{
			printEntries();
		}
	}

	std::cout << "End of scan:" << std::endl;
	printEntries();
}


Prober::~Prober()
{
}

/* \Brief Prints a header and the entries for the interface target data
*	No input and no output
*/
void Prober::printEntries()
{
	// Print header
	std::cout << std::left << std::setw(15) << "IP" <<
		" * " << std::setw(17) << "MAC" <<
		" * " << std::setw(26) << "Vendor" << std::setw(18) <<
		" Gratious/Sender/Target" << std::endl;

	// Print entries
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
