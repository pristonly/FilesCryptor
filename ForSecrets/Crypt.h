#pragma once
#include <vector>
#if defined( CRYPT )
#define IMPORT_EXPORT __declspec(dllexport)
#else
#define IMPORT_EXPORT __declspec(dllimport)
#endif

class IMPORT_EXPORT AES
{
public:
	AES();
	virtual ~AES() { Clear(); };
	void Init(const std::vector<unsigned char>& crypt);
	void InitKey(const std::vector<unsigned char>& key);
	virtual void Encrypt() = 0;
	virtual void Decrypt() = 0;
	virtual std::vector<unsigned char>& GetData() = 0;
	void Clear();


protected:
	void InitParametra(unsigned char Nk, unsigned char Nr);
	void _Encrypt();
	void _Decrypt();
	std::vector<unsigned char>& _GetData() { return _data; };

private:
	//Functions
	void CryptExtens();
	void AddRoundKey(size_t block, size_t iteration);
	void SubBytes(size_t block);
	void InvSubBytes(size_t block);
	void ShiftRows(size_t block);
	void InvShiftRows(size_t block);
	void InitTMul();
	void MixColumns(size_t block);
	void InvMixColumns(size_t block);
	void CreateKeyShed();
	void Transpon();
	void InvTranspon();
	unsigned char xtime(unsigned char b);
	unsigned char xmul(unsigned char a, unsigned char b);
	unsigned char GetState(size_t c, size_t r, size_t block);
	unsigned char _getSBoxValue(unsigned char num) { return sbox[num]; }
	size_t RotWord(size_t a);
	size_t SubWordShed(size_t a);

	//For User
	std::vector<unsigned char> _data;
	std::vector<unsigned char> _key;
	std::vector<unsigned int> _w;

	//Constants
	unsigned char sbox[256];
	unsigned char rsbox[256];
	unsigned char tMul[256][256];
	unsigned char Nb;
	unsigned char Nk;
	unsigned char Nr;
	size_t Rcon[11];
};

class IMPORT_EXPORT AES128 : public AES
{
public:
	AES128() { InitParametra(4, 10); }
	void Encrypt() override { _Encrypt(); }
	void Decrypt() override { _Decrypt(); }
	std::vector<unsigned char>& GetData() override { return _GetData(); }
};

class IMPORT_EXPORT AES192 : public AES
{
public:
	AES192() { InitParametra(6, 12); }
	void Encrypt() override { _Encrypt(); }
	void Decrypt() override { _Decrypt(); }
	std::vector<unsigned char>& GetData() override { return _GetData(); }
};

class IMPORT_EXPORT AES256 : public AES
{
public:
	AES256() { InitParametra(8, 14); }
	void Encrypt() override { _Encrypt(); }
	void Decrypt() override { _Decrypt(); }
	std::vector<unsigned char>& GetData() override { return _GetData(); }
};

class IMPORT_EXPORT AES_CBC
{
public:
	virtual ~AES_CBC() { Clear(); };
	void Init(const std::vector<unsigned char>& crypt) { _data = crypt; }
	void InitKey(const std::vector<unsigned char>& key) { _key = key; }
	void InitVec(const std::vector<unsigned char>& initvec) { _InitVec = initvec; }
	void Encrypt();
	void Decrypt();
	void Clear() { _data.clear(); _key.clear(); _InitVec.clear(); delete _blocks; }
	std::vector<unsigned char>& GetData() { return _data; };
protected:
	virtual void InitVers() = 0;
	void CryptExtens();
	AES* _blocks;
private:
	std::vector<unsigned char> _InitVec;
	std::vector<unsigned char> _data;
	std::vector<unsigned char> _key;
};

class IMPORT_EXPORT AES_CBC_128 : public AES_CBC
{
public:
	AES_CBC_128() { InitVers(); }
protected:
	void InitVers() override { _blocks = new AES128; }
};

class IMPORT_EXPORT AES_CBC_192 : public AES_CBC
{
public:
	AES_CBC_192() { InitVers(); }
protected:
	void InitVers() override { _blocks = new AES192; }
};

class IMPORT_EXPORT AES_CBC_256 : public AES_CBC
{
public:
	AES_CBC_256() { InitVers(); }
protected:
	void InitVers() override { _blocks = new AES256; }
};

class IMPORT_EXPORT MD5
{
public:
	MD5() = default;
	void Init(std::vector<unsigned char>& data) { _data = data; }
	void MakeHash();
	void Clear() { _data.clear(); }
	unsigned char* GetData() { return m_hash; }
	~MD5() { Clear(); }
private:
	void Addict();
	unsigned int A0 = 0X67452301;
	unsigned int B0 = 0xefcdab89;
	unsigned int C0 = 0x98badcfe;
	unsigned int D0 = 0x10325476;
	std::vector<unsigned char> _data;
	unsigned char m_hash[16];
};