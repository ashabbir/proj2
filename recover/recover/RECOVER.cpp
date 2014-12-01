
//  recover.cpp
//  Created by Ahmed Shabbir on 11/30/14.
//  Copyright (c) 2014 NYU. All rights reserved.



#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <fstream>
#include <cerrno>
#include <iostream>
#include <string>

using namespace std;
using std::string;


#include <cstdlib>


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
#include "base32.h"

using namespace CryptoPP;


std::string get_file_contents(const char *filename)
{
    std::ifstream in(filename, std::ios::in | std::ios::binary);
    if (in)
    {
        std::string contents;
        in.seekg(0, std::ios::end);
        contents.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&contents[0], contents.size());
        in.close();
        return(contents);
    }
    cout << "file not found" << endl;
    throw(errno);
}


void save_file(const char *filename, string data){
    std::ofstream outfile(filename);
    outfile << data;
    outfile.close();
}




int main(int argc, char* argv[])
{
    
    
    if (argc < 4) {
        std::cerr << argc <<endl <<"Usage: " << argv[0] <<endl;
        return 1;
    }
    
    
    //cout << "0: " << argv[0]<< endl << "1: " <<argv[1] << endl << "2: " <<argv[2]<< endl << "3: " <<argv[3] << endl;
    
    
    string cipher, cipher_hex ,iv_hex, iv ,messege , filename , filename2 , fkey, fkey_hex , message;
    AutoSeededRandomPool prng;
    
    
    //string base_path = "/Users/avp/Dropbox/Projects/Cryptography/NewProject2/proj2/";
    string base_path = "/Users/amd/code/cpp/proj2/";
    
    //string fkey_path = base_path + argv[3];
    string fkey_path = base_path + "key.txt";
    string efile_path = base_path + argv[1];
    string efilename_path = base_path + argv[2];
    string temp_filename = argv[1];
    temp_filename.erase(0,1);
    string sfile_path = base_path + "s" + temp_filename;
    
    
    //cout << "0: " << key_path << endl << "1: " << file_path << endl << "2: " <<  cypher_path << endl << "3: " << filename_path << endl;
    
    fkey_hex = get_file_contents(fkey_path.c_str());
    cipher_hex = get_file_contents(efile_path.c_str());

    iv_hex = cipher_hex.substr(0, 32);
    StringSource(iv_hex, true,
                 new HexDecoder(
                                new StringSink(iv)
                                ) // HexEncoder
                 ); // StringSource

    
    cipher_hex.erase(0, 32);
    StringSource(cipher_hex, true,
                 new HexDecoder(
                                new StringSink(cipher)
                                ) // HexEncoder
                 ); // StringSource

    
    
    StringSource(fkey_hex, true,
                 new HexDecoder(
                                new StringSink(fkey)
                                ) // HexEncoder
                 ); // StringSource

    //cout << fkey_hex<< endl << fkey <<endl;
    
    try
    {
        //decrypt using key need to change this
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV((byte*)fkey.c_str(), fkey.size(), (byte*)iv.c_str());
        
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(message)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
#if 0
        StreamTransformationFilter filter(d);
        filter.Put((const byte*)cipher, cipher.size());
        filter.MessageEnd();
        
        const size_t ret = filter.MaxRetrievable();
        recovered.resize(ret);
        filter.Get((byte*)recovered.data(), recovered.size());
#endif
        
        
        save_file( sfile_path.c_str(), message);
        cout << "RECOVERED !!!" << endl;

    }
    catch (const CryptoPP::Exception& d)
    {
        cerr << d.what() << endl;
        exit(1);
    }
    
    return 0;
}