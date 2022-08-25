#pragma once
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>


struct Uncrypted
{
	std::string m_FileName;
	std::string m_path;
	uint64_t size;
	std::vector<unsigned char> buffer;
};

class Reader
{
public:
	Reader();
	void Init(const std::vector<std::string>& paths);
	void GetContent();
	void Clear();
	~Reader();
private:
	std::vector<Uncrypted> m_files;
};