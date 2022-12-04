#define READER
#include "ReadFiles.h"


Reader::Reader()
{

}

Reader::~Reader()
{
	m_files.clear();
}

void Reader::Init(const std::vector<std::string>& paths)
{
	m_files.reserve(paths.size());
	for (const auto& path : paths)
	{
		std::filesystem::path fileinfo(path);
		m_files.emplace_back(Uncrypted());
		m_files.back().m_path = path;
		m_files.back().m_FileName = fileinfo.filename().string();
		m_files.back().m_sizeFileName = m_files.back().m_FileName.size();
		m_files.back().m_sizepath = m_files.back().m_path.size();
	}
}

void Reader::GetContent()
{
	for (auto& unions : m_files)
	{
		std::ifstream file(unions.m_path, std::ios_base::in | std::ios_base::binary);

		if (file.is_open())
		{
			std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
			unions.size = buffer.size();
			unions.buffer = std::move(buffer);
		}

		file.close();
	}
}

std::vector<unsigned char> Reader::ConverTo()
{
	std::vector<unsigned char> buff;
	//buff.emplace_back(0xff); buff.emplace_back(0xfe); buff.emplace_back(0xff);
	for (const auto& unions : m_files)
	{
		for(size_t i = 0; i < 4; ++i)
			buff.emplace_back(GetByte(unions.m_sizepath, i));
		for(const auto& str : unions.m_path)
			buff.emplace_back((unsigned char)str);
		for (size_t i = 0; i < 4; ++i)
			buff.emplace_back(GetByte(unions.m_sizeFileName, i));
		for (const auto& str : unions.m_FileName)
			buff.emplace_back(str);
		for (size_t i = 0; i < 8; ++i)
			buff.emplace_back(GetByte(unions.size, i));
		for (const auto& str : unions.buffer)
			buff.emplace_back(str);
	}
	return buff;
}

void Reader::Clear()
{
	m_files.clear();
}



