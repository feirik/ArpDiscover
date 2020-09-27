#include "Prober.h"

#include "PcapController.h"

#include <iostream>



Prober::Prober(UserInput inputs)
{
	std::cout << "Started prober class" << std::endl;

	m_inputs = inputs;

	std::cout << "Passive: " << inputs.passiveFlag << " Interface: " << inputs.interfaceIn << std::endl;

	while (1)
	{
		PcapController controller;
	}
}


Prober::~Prober()
{
}
