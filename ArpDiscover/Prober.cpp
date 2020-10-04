#include "Prober.h"

#include "PcapController.h"

#include <iostream>



Prober::Prober(userInput inputs)
{
	std::cout << "Started prober class" << std::endl;

	m_targetData.reserve(8);

	m_inputs = inputs;

	std::cout << "Passive: " << inputs.passiveFlag << " Interface: " << inputs.interfaceIn << std::endl;

	/*while (1)
	{
		PcapController controller(&m_targetData);
	}*/

	PcapController controller(&m_targetData);

	while (1);
}


Prober::~Prober()
{
}
