#pragma once

#include <vector>
#include <ymath.h>

std::vector<unsigned char> _DecToBin(unsigned char dec)
{
	unsigned char buff = dec;
	size_t i = 0;
	std::vector<unsigned char> bin;
	bin.reserve(8);

	while (i < 8)
	{
		unsigned char reminder = buff % 2;
		buff /= 2;
		bin.emplace_back(reminder);
		++i;
	}

	return bin;
}

unsigned char _BinToDec(const std::vector<unsigned char>& bin)
{
	unsigned char dec = 0;

	for (size_t i = 0; i < bin.size(); ++i)
	{
		if(bin[i] == 1)
			dec += pow(2,  i);
	}
	return dec;
}


