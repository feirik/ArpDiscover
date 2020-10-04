#pragma once

#include "Misc.h"

#include <vector>

struct captureData
{
	std::string ip;
	std::string MAC;
	std::string vendor;
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

