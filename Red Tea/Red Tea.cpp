// Red Tea.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include "Crypt.h"

int main()
{
    AES_CBC_128 test;
    MD5 test_md5;
    std::vector<unsigned char> message{'H', 'E', 'L', 'L', 'O', ' ', 'W', 'O', 'R', 'L', 'D', '!'};
    std::vector<unsigned char> key{'m', 'b', 'z', 'v', 'n', 'v', 'c', '5', 'g', 0x60, 0x11, 0x12, 0x13, 0x15, 0xa0, 0xff};
    std::vector<unsigned char> initvec{ 0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x11, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e };
    std::vector<unsigned char> md{ 'm', 'd', '5' };
    test.Init(message);
    test.InitKey(key);
    test.InitVec(initvec);
    test.Encrypt();
    std::vector<unsigned char> encrypt = test.GetData();
    test.Init(encrypt);
    test.InitKey(key);
    test.InitVec(initvec);
    test.Decrypt();
    std::vector<unsigned char> decrypt = test.GetData();
    test_md5.Init(md);
    test_md5.MakeHash();
    return 0;
}
