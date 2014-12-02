//  Created by Ahmed Shabbir on 11/28/14.
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

#include "files.h"
#include "modes.h"
#include "base32.h"

using namespace CryptoPP;



//GENERAL FUNCTIONS TO SAVE FILE OPEN FILE
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
    cout << "file not found " << filename << endl;
    throw(errno);
}

//GENERAL FUNCTIONS TO SAVE FILE OPEN FILE
void save_file(const char *filename, string data){
    std::ofstream outfile(filename);
    outfile << data;
    outfile.close();
}




int main(int argc, char* argv[])
{
    //CHECK PARAMS
    if (argc < 4) {
        std::cerr <<"Usage: ./preprocess	key.txt   file.txt   filename.txt   (returning files efile.txt and efilename.txt) " << endl;
        return 1;
    }
    
    string base_path = "./";
#ifdef DEBUG
    base_path =  __FILE__ ;
    base_path = base_path.replace(base_path.find("/preprocess/preprocess/preprocess.cpp"), sizeof("/preprocess/preprocess/preprocess.cpp")-1, "/");
#endif
    
    string cipher, cipher_hex , iv_hex, key , key_hex , messege, iv_cipher_hex, filename , filename2;
    AutoSeededRandomPool prng;
    

    
    string key_path = base_path + argv[1];
    string file_path = base_path + argv[2];
    string cypher_path = base_path + "e" + argv[2];
    string filename_path = base_path + argv[3];
    string filename2_path = base_path + "e" + argv[3];
    
    
    
    key_hex = get_file_contents(key_path.c_str());
    messege = get_file_contents(file_path.c_str());
    filename = get_file_contents(filename_path.c_str());
    
    
    //REGION GENERATE NEW FILENAME
    try
    {
        StringSource(filename, true,
                     new HexEncoder(
                                    new StringSink(filename2)
                                    ) // HexEncoder
                     );
    }
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    save_file(filename2_path.c_str() , filename2);
    
    //GENERATE IV
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    
    StringSource(iv, sizeof(iv), true,
                 new HexEncoder(
                                new StringSink(iv_hex)
                                ) // HexEncoder
                 ); // StringSource

   
    try
    {
        
        //cout << key_hex << endl;
        //example taken from cryptowiki
        StringSource(key_hex, true,
                     new HexDecoder(
                                    new StringSink(key)
                                    ) // HexEncoder
                     ); // StringSource

        //cout << key << endl;
        
        //encrypt
        CBC_Mode< AES> ::Encryption e;
        e.SetKeyWithIV((byte*)key.c_str(), key.size(), iv);
        
        //remove padding.
        StringSource s(messege, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
#if 0
        StreamTransformationFilter filter(e);
        filter.Put((const byte*)plain.data(), plain.size());
        filter.MessageEnd();
        
        const size_t ret = filter.MaxRetrievable();
        cipher.resize(ret);
        filter.Get((byte*)cipher.data(), cipher.size());
#endif
    }
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    //example taken from cryptowiki
    StringSource(cipher, true,
                 new HexEncoder(
                                new StringSink(cipher_hex)
                                ) // HexEncoder
                 ); // StringSource
    //cout  << cipher_hex << endl;
    
    
    iv_cipher_hex = iv_hex + cipher_hex;
    
    //save cypherfile
    save_file(cypher_path.c_str() , iv_cipher_hex);
    

    //cout << cipher <<endl << cipher_hex <<endl << iv_cipher_hex <<endl  ;
    cout << "ENCRYPTED !!!!" << endl << cypher_path  <<endl << filename2_path << endl  ;
    
    return 0;
}