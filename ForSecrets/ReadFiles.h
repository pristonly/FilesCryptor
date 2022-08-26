#pragma once
#if defined( READER )
#define IMPORT_EXPORT __declspec(dllexport)
#else
#define IMPORT_EXPORT __declspec(dllimport)
#endif
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>


struct Uncrypted
{
	size_t m_sizeFileName;
	std::string m_FileName;
	size_t m_sizepath;
	std::string m_path;
	uint64_t size;
	std::vector<unsigned char> buffer;
};

class IMPORT_EXPORT Reader
{
public:
	Reader();
	void Init(const std::vector<std::string>& paths);
	void GetContent();
	void Clear();
	std::vector<unsigned char> ConverTo();
	~Reader();
private:
	std::vector<Uncrypted> m_files;
};
