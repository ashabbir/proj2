
//  Created by Ahmed Shabbir on 11/28/14.
//  Copyright (c) 2014 NYU. All rights reserved.
//  KeyGen.cpp : Defines the entry point for the console application.


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

#include "files.h"
#include "modes.h"

using namespace CryptoPP;


int main(int argc, char* argv[])
{
    string base_path = "./";
#ifdef DEBUG
    base_path =  __FILE__ ;
    base_path = base_path.replace(base_path.find("/keygen/keygen/keygen.cpp"), sizeof("/keygen/keygen/keygen.cpp")-1, "/");
#endif
    
    AutoSeededRandomPool prng;
    string key_hex;
    
    
    //generate key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    
    //convert key into hex so we have save it to the file (sample taken from cryptopp manpages)
    key_hex.clear();
    StringSource(key, key.size(), true,
                 new HexEncoder(
                                new StringSink(key_hex)
                                ) // HexEncoder
                 );
    
    
    //save the key file in hex format
    string key_path = base_path + "key.txt";
    std::ofstream outfile(key_path);
    outfile << key_hex;
    outfile.close();
    
    cout << "KEY GENERATED: " << endl ;
    return 0;
}