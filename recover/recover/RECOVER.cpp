
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

#include <stdio.h>  /* defines FILENAME_MAX */
#ifdef WINDOWS
    #include <direct.h>
    #define GetCurrentDir _getcwd
#else
    #include <unistd.h>
    #define GetCurrentDir getcwd
#endif


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
    cout << "file not found" << filename << endl;
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
    
    
    string base_path = "./";
#ifdef DEBUG
    cout << "running in debug" << endl;
//    base_path = "/Users/amd/code/cpp/proj2/";
    base_path = "/Users/ahmed/nyu/classes/crypto/proj2/";
    // base_path = "/Users/avp/Dropbox/Projects/Cryptography/NewProject2/proj2/";
#endif
    string fkey_path = base_path + argv[3];
    string efile_path = base_path + argv[1];
    string efilename_path = base_path + argv[2];
    string temp_filename = argv[1];
    temp_filename.erase(0,1);
    string sfile_path = base_path + "s" + temp_filename;



    
    //cout << "0: " << key_path << endl << "1: " << file_path << endl << "2: " <<  cypher_path << endl << "3: " << filename_path << endl;
    
    string temp_fkey_hex = get_file_contents(fkey_path.c_str());
    try
    {
        StringSource(temp_fkey_hex, true,
                     new HexDecoder(
                                    new StringSink(fkey_hex)
                                    )
                     );
    }
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //cout << temp_fkey_hex << " : read" << endl;
    //cout << fkey_hex <<  " : converted " <<endl;
    
    string fname =  get_file_contents(efilename_path.c_str());
    //cout << "efilename " << fname << endl;

    
    //get the key from fkey (key = fkey xor efilename)
    string pad_fname = fkey_hex;

    float key_len = fkey_hex.length() ;
    
    int i =0;
    for (int x = 0; x < key_len; x ++ ) {
        pad_fname[x] = fname[i];
        i++;
        if ( i >= strlen(fname.c_str())){
            i=0;
        }
    }
    cout << "pad filename " << pad_fname << endl;
    string recovered_key = fkey_hex;
    for(int x=0; x<key_len; x++)
    {
        recovered_key[x]=fkey_hex[x]^pad_fname[x];
    }
    
    cout << "rkey  " << recovered_key << endl;
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

    
    
    StringSource(recovered_key, true,
                 new HexDecoder(
                                new StringSink(fkey)
                                ) // HexEncoder
                 ); // StringSource

    cout << fkey_hex<< endl << fkey <<endl;
    
    try
    {
        cout << "*" << endl;
        //decrypt using key need to change this
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV((byte*)fkey.c_str(), fkey.size(), (byte*)iv.c_str());
        
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(message)
                                                      ) // StreamTransformationFilter
                       );

        
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
        cout << "*" << endl;
        cerr << d.what() << endl;
        exit(1);
    }
    
    return 0;
}