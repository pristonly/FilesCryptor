#include "WriteFiles.h"

void WriteFile(std::vector<unsigned char>& buff, std::string& path)
{
	std::fstream file(path, std::ios::binary | std::ios::out);

	for (size_t i = 0; i < buff.size(); ++i)
	{
		file.write((char*)&buff[i], sizeof(unsigned char));
	}

	file.close();
}