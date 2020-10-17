#pragma once

#include "Misc.h"

#include <vector>

struct arpEvent
{
	bool sender = false;
	bool target = false;
	bool gratious = false;
};

struct captureData
{
	std::string ip;
	std::string MAC;
	std::string vendor;

	arpEvent arpEvent;
};

class Prober
{
public:
	Prober(userInput inputs);
	~Prober();

private:
	userInput m_inputs;

	std::vector<captureData> m_targetData;
};

