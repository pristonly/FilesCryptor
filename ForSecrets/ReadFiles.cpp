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

void Reader::Clear()
{
	m_files.clear();
}



