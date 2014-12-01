//
//  main.cpp
//  keygen
//
//  Created by Ahmed Shabbir on 11/30/14.
//  Copyright (c) 2014 NYU. All rights reserved.
//
// KeyGen.cpp : Defines the entry point for the console application.
//

//
//  main.cpp
//  crypto_test
//
//  Created by Ahmed Shabbir on 11/28/14.
//  Copyright (c) 2014 NYU. All rights reserved.
//



#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "aes.h"
using CryptoPP::AES;

#include "gcm.h"
using CryptoPP::GCM;

#include "secblock.h"
using CryptoPP::SecByteBlock;



#include "rsa.h"
#include "files.h"
#include "modes.h"

using namespace CryptoPP;


int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;
    string cipher, encoded;
    
    //generate key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    
    // Pretty print key
    encoded.clear();
    StringSource(key, key.size(), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    cout << "key: " << encoded << endl;
    
    
    std::ofstream outfile("/Users/amd/code/cpp/proj2/key.txt");
    outfile << encoded;
    outfile.close();
    
    cout << "KEY GENERATED !!!!" <<endl  ;
    return 0;
}