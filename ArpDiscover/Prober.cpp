#include "Prober.h"

#include "PcapController.h"

#include <iostream>



Prober::Prober(userInput inputs) : m_inputs(inputs)
{
	m_targetData.reserve(8);

	//std::cout << "Passive: " << inputs.passiveFlag << " Interface: " << inputs.interfaceIn << std::endl;

	/*while (1)
	{
		PcapController controller(&m_targetData);
	}*/

	PcapController controller(&m_targetData);

	for (int i = 0; i < 10; ++i)
	{
		controller.capturePackets();

		if (controller.getIsEntryAdded() == true)
		{
			controller.printEntries();
		}
	}

	while (1);
}


Prober::~Prober()
{
}
