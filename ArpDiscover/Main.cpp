#include <stdio.h>

#include <iostream>

#include "Prober.h"
#include "Misc.h"

#include "CLI11.hpp"

int main(int argc, char* argv[])
{
	userInput inputs;

	CLI::App app("ARP monitor for tracking changes to the ARP cache.");

	app.add_option("-i,--interface", inputs.interfaceIn, "Set specific interface IP address to monitor.");
	//app.add_flag("-a,--active", inputs.activeFlag, "Not implemented");

	CLI11_PARSE(app, argc, argv);

	//printf("Interface: %s Passivelflag: %u\n", inputs.interfaceIn.c_str(), inputs.passiveFlag);

	Prober prober(inputs);

	std::cin.get();

	return 0;
}