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

	CLI11_PARSE(app, argc, argv);

	Prober prober(inputs);

	return 0;
}