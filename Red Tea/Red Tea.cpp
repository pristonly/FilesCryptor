#pragma warning( disable : 4251)

#include <iostream>
#include <chrono>

#include "ReadFiles.h"
#include "Crypt.h"

int main()
{
    AES_CBC_128 test;
    MD5 test_md5;
    Reader test_reader;

    std::vector<unsigned char> message{'H', 'E', 'L', 'L', 'O', ' ', 'W', 'O', 'R', 'L', 'D', '!'};
    std::vector<unsigned char> key{'m', 'b', 'z', 'v', 'n', 'v', 'c', '5', 'g', 0x60, 0x11, 0x12, 0x13, 0x15, 0xa0, 0xff};
    std::vector<unsigned char> initvec{ 0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x11, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e };
    std::vector<unsigned char> md{'m', 'd', '5'};
    std::vector<std::string> path{ "C:\\Users\\prist\\MyProjects\\ForSecrets\\ForSecrets\\1.png", "C:\\Users\\prist\\MyProjects\\ForSecrets\\ForSecrets\\2.png" , "C:\\Qt\\MaintenanceTool.exe",
    "D:\\boost.zip"};

    /*test_reader.Init(path);
    test_reader.GetContent();
    std::vector<unsigned char> test_reader_convert = std::move(test_reader.ConverTo());*/

    test_md5.Init(md);
    test_md5.MakeHash();

    //using namespace std::chrono;

    //high_resolution_clock::time_point t1 = high_resolution_clock::now();

    //test.Init(std::move(test_reader_convert));
    //test.InitKey(key);
    //test.InitVec(initvec);
    //test.Encrypt();

    //test.InitKey(key);
    //test.InitVec(initvec);
    //test.Decrypt();

    //high_resolution_clock::time_point t2 = high_resolution_clock::now();
    //duration<double> time_span = duration_cast<duration<double>>(t2 - t1);

    //std::cout << "It took me " << time_span.count() << " seconds.";
    //std::cout << std::endl;

    //std::vector<unsigned char> decrypt = std::move(test.GetData()); 


    return 0;
}
