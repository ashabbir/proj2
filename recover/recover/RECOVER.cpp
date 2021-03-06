
//  recover.cpp
//  Created by Ahmed & Anshul on 11/30/14.
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


//GENERIC SAVE READ FILE
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

    //CHECK PARAMS
    if (argc < 4) {
        std::cerr <<"Usage: ./recover	efile.txt   efilename.txt   fkey.txt" << endl;
        return 1;
    }
    
    
    string cipher, cipher_hex ,iv_hex, iv ,messege , filename , filename2 , fkey, fkey_hex , message;
    AutoSeededRandomPool prng;
    
    //SET PATHS
    string base_path = "./";
#ifdef DEBUG
    base_path =  __FILE__ ;
    base_path = base_path.replace(base_path.find("/recover/recover/recover.cpp"), sizeof("/recover/recover/recover.cpp")-1, "/");
#endif
    
    string fkey_path = base_path + argv[3];
    string efile_path = base_path + argv[1];
    string efilename_path = base_path + argv[2];
    string temp_filename = argv[1];
    temp_filename.erase(0,1);
    string sfile_path = base_path + "s" + temp_filename;



    //read fkey and hexdecode it
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

    float key_len = fkey_hex.length() ;
    
    
    //read filename and pad legth should be atleast equal key
    string fname =  get_file_contents(efilename_path.c_str());
    string pad_fname = fkey_hex;
    
    int i =0;
    for (int x = 0; x < key_len; x ++ ) {
        pad_fname[x] = fname[i];
        i++;
        if ( i >= strlen(fname.c_str())){
            i=0;
        }
    }
    
    //get the key from fkey (key = fkey xor efilename)
    string recovered_key = fkey_hex;
    for(int x=0; x<key_len; x++)
    {
        recovered_key[x]=fkey_hex[x]^pad_fname[x];
    }
    

    //get cipher text
    cipher_hex = get_file_contents(efile_path.c_str());
    
    
    //extract iv
    iv_hex = cipher_hex.substr(0, 32);
    StringSource(iv_hex, true,
                 new HexDecoder(
                                new StringSink(iv)
                                ) // HexEncoder
                 ); // StringSource

    //remove iv from cipher
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

    
    try
    {
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
        cout << "RECOVERED !!!" << endl ;

    }
    catch (const CryptoPP::Exception& d)
    {
        cout << "*" << endl;
        cerr << d.what() << endl;
        exit(1);
    }
    
    return 0;
}