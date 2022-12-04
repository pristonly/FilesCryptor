#define CRYPT
#pragma warning( disable : 4251)
#include "Crypt.h"
#include <cstdlib>

inline constexpr unsigned char operator "" _uchar( unsigned long long arg ) noexcept
{
    return static_cast< unsigned char >( arg );
}

void AES::Init(const std::vector<unsigned char>& crypt)
{
	_data = crypt;
}

void AES::Init(std::vector<unsigned char> && crypt) noexcept
{
	_data = std::move(crypt);
}

void AES::InitKey(const std::vector<unsigned char>& key)
{
	_key = key;
}

void AES::InitParametra(unsigned char Nk, unsigned char Nr)
{
	this->Nk = Nk;
	this->Nr = Nr;
}

AES::AES() : 
	sbox {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 },
	rsbox {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d },
	Rcon
	{
    0x00, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
	},
	Nb(4), Nk(4), Nr(10) ,tMul{0}
{
	InitTMul();
}

void AES::Transpon()
{
	unsigned char temp = 0;

	for (size_t i = 0; i < _data.size() / 16; ++i)
	{
		for (size_t j = 0; j < Nb; ++j)
		{
			for (size_t z = 0; z < j; ++z)
			{
				temp = _data[i * Nb * Nb + j * Nb + z];
				_data[i * Nb * Nb + j * Nb + z] = _data[i * Nb * Nb + z * Nb + j];
				_data[i * Nb * Nb + z * Nb + j] = temp;
			}
		}
	}
}

void AES::InvTranspon()
{
	unsigned char temp = 0;

	for (size_t i = 0; i < _data.size() / 16; ++i)
	{
		for (size_t j = 0; j < Nb; ++j)
		{
			for (size_t z = 0; z < j; ++z)
			{
				temp = _data[i * Nb * Nb + j * Nb + z];
				_data[i * Nb * Nb + j * Nb + z] = _data[i * Nb * Nb + z * Nb + j];
				_data[i * Nb * Nb + z * Nb + j] = temp;
			}
		}
	}
}

void AES::CryptExtens()
{
	unsigned char ext = _data.size() % 16;
	if (ext == 0)
	{
		return;
	}
	size_t start_pos = _data.size();
	_data.resize(_data.size() + 16_uchar - ext);

	for (; start_pos < _data.size(); ++start_pos)
		_data[start_pos] = static_cast<unsigned char>(rand() % 255);
}

unsigned char AES::GetState(size_t c, size_t r, size_t block)
{
	return _data[r + 4  * c + block * 16L];
}


void AES::AddRoundKey(size_t block, size_t iteration)
{
	for (int i = 0; i < Nb; i++) {
		unsigned int temp;
		temp = ((0x0L ^ GetState(0, i, block)) << 24) ^ ((0x0L ^ GetState(1, i, block)) << 16) ^ ((0x0L ^ GetState(2, i, block)) << 8) ^ ((0x0L ^ GetState(3, i, block)));
		temp ^= (unsigned int)_w[i + iteration * Nb];
		_data[i + 4 * 0 + block * 16L] = (temp >> 24) & 0xff;
		_data[i + 4 * 1 + block * 16L] = (temp >> 16) & 0xff;
		_data[i + 4 * 2 + block * 16L] = (temp >> 8) & 0xff;
		_data[i + 4 * 3 + block * 16L] = (temp) & 0xff;
	};
}

void AES::SubBytes(size_t block)
{
	for (size_t i = 0; i < (size_t)(Nb * Nb); ++i)
	{
		_data[i + block * Nb * Nb] = sbox[_data[i + block * Nb * Nb]];
	}
}

void AES::ShiftRows(size_t block)
{
	unsigned char temp[16];

	for (size_t i = 0; i < 4; ++i)
		temp[i] = _data[block * Nb * Nb + i];

	temp[7] = _data[block * Nb * Nb + 4];

	for (size_t i = 5; i < 8; ++i)
		temp[i - 1] = _data[block * Nb * Nb + i];

	temp[10] = _data[block * Nb * Nb + 8];
	temp[11] = _data[block * Nb * Nb + 9];

	for (size_t i = 10; i < 12; ++i)
		temp[i - 2] = _data[block * Nb * Nb + i];

	temp[12] = _data[block * Nb * Nb + 15];
	temp[13] = _data[block * Nb * Nb + 12];
	temp[14] = _data[block * Nb * Nb + 13];
	temp[15] = _data[block * Nb * Nb + 14];

	for (size_t i = 0; i < 16; ++i)
		_data[block * Nb * Nb + i] = temp[i];

}

unsigned char AES::xtime(unsigned char b)
{
	return (((b & 0x80) == 0) ? (b << 1) : ((b << 1) ^ 0x1b));
}

unsigned char AES::xmul(unsigned char a, unsigned char b)
{
	unsigned char t = 0x00;
	unsigned char x[8];

	x[0] = a;

	for (size_t i = 1; i < 8; ++i)
		x[i] = xtime(x[i - 1]);

	for (size_t i = 0; i < 8; ++i)
	{
		if ((b & 0x01) != 0)
			t ^= x[i];
		b = b >> 1;
	}
	return t;
}

void AES::InitTMul()
{
	for (size_t i = 0; i <= 0xff; ++i)
		for (size_t j = 0; j <= 0xff; ++j)
			tMul[i][j] = xmul(i, j);
}

void AES::MixColumns(size_t block)
{
	unsigned char temp[4];
	for (size_t c = 0; c < 4; ++c)
	{
		temp[0] = (tMul[0x02][_data[block * 16 + c]]) ^ (tMul[0x03][_data[block * 16 + 4 + c]]) ^ _data[block * 16 + 8 + c] ^ _data[block * 16 + 12 + c];
		temp[1] = (tMul[0x02][_data[block * 16 + 4 + c]]) ^ (tMul[0x03][_data[block * 16 + 8 + c]]) ^ _data[block * 16 + c] ^ _data[block * 16 + 12 + c];
		temp[2] = (tMul[0x02][_data[block * 16 + 8 + c]]) ^ (tMul[0x03][_data[block * 16 + 12 + c]]) ^ _data[block * 16 + c] ^ _data[block * 16 + 4 + c];
		temp[3] = (tMul[0x02][_data[block * 16 + 12 + c]]) ^ (tMul[0x03][_data[block * 16 + c]]) ^ _data[block * 16 + 4 + c] ^ _data[block * 16 + 8 + c];

		for (size_t i = 0; i < 4; ++i)
		{
			_data[block * 16 + i * 4 + c] = temp[i];
		}
	}
}

size_t AES::RotWord(size_t a)
{
	size_t temp = (a >> 24) & 0xff;

	a = (a << 8) ^ temp;

	return a;
}

size_t AES::SubWordShed(size_t a)
{
	unsigned char temp[4];
	size_t output;
	
	for (size_t i = 0; i < 4; ++i)
	{
		temp[i] = (a >> i * 8) & 0xff;
		temp[i] = _getSBoxValue(temp[i]);
	}

	output = (temp[0] ^ 0x00L) ^ ((temp[1] ^ 0x00L) << 8) ^ ((temp[2] ^ 0x00L) << 16) ^ ((temp[3] ^ 0x00L) << 24);

	return output;
}

void AES::CreateKeyShed()
{
	_w.resize(Nb*(Nr + 1));
	size_t temp = 0x00L;

	for (size_t i = 0; i < Nk; ++i)
	{
		_w[i] = ((0x0L ^ _key[i * 4]) << 24) ^ ((0x0L ^ _key[i * 4 + 1]) << 16) ^ ((0x0L ^ _key[i * 4 + 2]) << 8) ^ ((0x0L ^ _key[i * 4 + 3]));
	}

	for (size_t i = Nk; i < (Nb * (Nr + 1)); ++i)
	{
		temp = _w[i - 1];

		if (i % Nk == 0)
			temp = SubWordShed(RotWord(temp)) ^ Rcon[i / Nk];

		if (Nk > 6 && i % Nk == 4)
			temp = SubWordShed(temp);

		_w[i] = _w[i - Nk] ^ temp;
	}
}

void AES::Clear()
{
	_w.clear();
	_data.clear();
	_key.clear();
}

void AES::_Encrypt()
{	
	CryptExtens();
	Transpon();
	CreateKeyShed();

	for (size_t block = 0; (block * 16) < _data.size(); ++block)
	{
		AddRoundKey(block, 0);

		for (size_t i = 1; i < (Nr); ++i)
		{
			SubBytes(block);
			ShiftRows(block);
			MixColumns(block);
			AddRoundKey(block, i);
		}

		SubBytes(block);
		ShiftRows(block);
		AddRoundKey(block, Nr);
	}

	_w.clear();
	_key.clear();
}

void AES::InvShiftRows(size_t block)
{
	for (size_t i = 1; i < Nb; ++i)
	{
		size_t temp = ((_data.data()[i * Nb + block * 16] ^ 0x00L) << 24) ^ ((_data.data()[i * Nb + 1 + block * 16] ^ 0x00L) << 16) ^ ((_data.data()[i * Nb + 2 + block * 16] ^ 0x00L) << 8) ^ ((_data.data()[i * Nb + 3 + block * 16] ^ 0x00L));
		for (size_t j = 1; j < (i + 1); ++j)
		{
			size_t lastbyte = (temp << 24) & 0xff000000;
			temp = (temp >> 8);
			temp = (temp & 0x00ffffff) ^ lastbyte;
		}

		_data.data()[i * Nb + block * 16] = (temp >> 24) & 0xff;
		_data.data()[i * Nb + 1 + block * 16] = (temp >> 16) & 0xff;
		_data.data()[i * Nb + 2 + block * 16] = (temp >> 8) & 0xff;
		_data.data()[i * Nb + 3 + block * 16] = (temp) & 0xff;
	}

}

void AES::InvSubBytes(size_t block)
{
	for (size_t i = 0; i < (size_t)(Nb * Nb); ++i)
	{
		_data[i + block * Nb * Nb] = rsbox[_data[i + block * Nb * Nb]];
	}
}

void AES::InvMixColumns(size_t block)
{
	for (size_t c = 0; c < 4; ++c)
	{
		unsigned char temp[4];

		temp[0] = (tMul[0x0e][_data[block * 16 + c]]) ^ (tMul[0x0b][_data[block * 16 + 4 + c]]) ^ (tMul[0x0d][_data[block * 16 + 8 + c]]) ^ (tMul[0x09][_data[block * 16 + 12 + c]]);
		temp[1] = (tMul[0x09][_data[block * 16 + c]]) ^ (tMul[0x0e][_data[block * 16 + 4 + c]]) ^ (tMul[0x0b][_data[block * 16 + 8 + c]]) ^ (tMul[0x0d][_data[block * 16 + 12 + c]]);
		temp[2] = (tMul[0x0d][_data[block * 16 + c]]) ^ (tMul[0x09][_data[block * 16 + 4 + c]]) ^ (tMul[0x0e][_data[block * 16 + 8 + c]]) ^ (tMul[0x0b][_data[block * 16 + 12 + c]]);
		temp[3] = (tMul[0x0b][_data[block * 16 + c]]) ^ (tMul[0x0d][_data[block * 16 + 4 + c]]) ^ (tMul[0x09][_data[block * 16 + 8 + c]]) ^ (tMul[0x0e][_data[block * 16 + 12 + c]]);

		for (size_t i = 0; i < 4; ++i)
		{
			_data[block * 16 + i * 4 + c] = temp[i];
		}
	}
}

void AES::_Decrypt()
{
	CreateKeyShed();

	for (size_t block = 0; (block * 16) < _data.size(); ++block)
	{
		AddRoundKey(block, Nr);

		for (size_t i = Nr - 1; i > 0; --i)
		{
			InvShiftRows(block);
			InvSubBytes(block);
			AddRoundKey(block, i);
			InvMixColumns(block);
		}

		InvShiftRows(block);
		InvSubBytes(block);
		AddRoundKey(block, 0);
	}
	InvTranspon();
	_w.clear();
	_key.clear();
}

void AES_CBC::CryptExtens()
{
	for (size_t i = 0; i < 16; ++i)
	{
		_data.insert(_data.begin() + i, _InitVec[i]);
	}

	unsigned char ext = _data.size() % 16;
	if (ext == 0)
	{
		return;
	}
	size_t start_pos = _data.size();
	_data.resize(_data.size() + 16_uchar - ext);

	for (; start_pos < _data.size(); ++start_pos)
		_data[start_pos] = static_cast<unsigned char>(rand() % 255);
}

void AES_CBC::Encrypt()
{
	CryptExtens();

	for (size_t block = 1; block < _data.size() / 16; ++block)
	{
		for (size_t i = 0; i < 16; ++i)
		{
			m_banch[i] = _data[(block - 1) * 16 + i] ^ _data[(block) * 16 + i];
		}

		_blocks->Init(std::move(m_banch));
		_blocks->InitKey(_key);
		_blocks->Encrypt();
		m_banch = std::move(_blocks->GetData());
		for (size_t i = 0; i < 16; ++i)
		{
			_data[(block) * 16 + i] = m_banch[i];
		}

		_blocks->Clear();
	}
}

void AES_CBC::Decrypt()
{
	for (size_t block = 1; block < _data.size() / 16; ++block)
	{
		for (size_t i = 0; i < 16; ++i)
		{
			m_banch[i] = _data[(block) * 16 + i];
		}

		_blocks->Init(std::move(m_banch));
		_blocks->InitKey(_key);
		_blocks->Decrypt();
		m_banch = std::move(_blocks->GetData());
		for (size_t i = 0; i < 16; ++i)
		{
			unsigned char buff = _data[(block) * 16 + i];
			_data[(block) * 16 + i] = m_banch[i] ^ _InitVec[i];
			_InitVec[i] = buff;
		}
		_blocks->Clear();
	}

	for (size_t i = 16; i < _data.size(); ++i)
	{
		_data[i - 16] = _data[i];
	}
	_data.resize(_data.size() - 16);
}

void MD5::Addict()
{
	size_t addictBytes =  _data.size() % 64;
	uint64_t len = _data.size();
	if (addictBytes == 56)
		_data.resize(_data.size() + 120, 0);
	else
	{
		if(addictBytes < 56)
			_data.resize(_data.size() + 56 - addictBytes, 0);
		else
			_data.resize(_data.size() + 56 - addictBytes, 0);
	}
	_data[len] = 0x80;

	for (size_t i = 0; i < 8; ++i)
	{
		if (i < 4)
			_data.emplace_back((unsigned char)(((len*8) >> (i * 8)) & 0xff));
		else
			_data.emplace_back(0);
	}
}

void MD5::MakeHash()
{
	Addict();
	unsigned int s[64] =
	{
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
	
	unsigned int K[64] =
	{
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	for (unsigned int i = 0; i < _data.size() / 64; ++i)
	{
		unsigned int M[16];
		unsigned int A = A0;
		unsigned int B = B0;
		unsigned int C = C0;
		unsigned int D = D0;
		for (unsigned int j = 0; j < 16; ++j)
		{
			M[j] = *((unsigned int*)(_data.data() + (64 * i + j * 4)));
		}
		for (unsigned int z = 0; z < 64; ++z)
		{
			unsigned int F, g;

			if (z >= 0 && z <= 15)
			{
				F = (B & C) | ((~B) & D);
				g = z;
			}
			if (z >= 16 && z <= 31)
			{
				F = (D & B) | ((~D) & C);
				g = (5 * z + 1) % 16;
			}
			if (z >= 32 && z <= 47)
			{
				F = B ^ C ^ D;
				g = (3 * z + 5) % 16;
			}
			if (z >= 48 && z <= 63)
			{
				F = C ^ (B | (~D));
				g = (7 * z) % 16;
			}
			F = F + A + K[z] + M[g];
			A = D;
			D = C;
			C = B;
			Cycle(F, s[z]);
			B = B + F;
		}
		A0 += A;
		B0 += B;
		C0 += C;
		D0 += D;
	}
	unsigned int* phash = (unsigned int *)m_hash;
	*phash = A0;
	*(phash + 1) = B0;
	*(phash + 2) = C0;
	*(phash + 3) = D0;
}

void MD5::Cycle(unsigned int& dig, unsigned int count)
{
	unsigned int temp = 0;
	for (; (int)count > 0; --count)
	{
		temp = (dig & 0x80000000) >> 31;
		dig = (dig << 1) | temp;
	}
}