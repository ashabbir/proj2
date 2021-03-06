//  authorize
//  Created by Anshul Vikram Pandey on 11/30/14.
//  Copyright (c) 2014 Anshul Vikram Pandey. All rights reserved.




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

#include<sstream>

using namespace CryptoPP;



//FUNCTION TO READ FILES AND RETURN DATA
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

//FUNCTION TO SAVE FILES
void save_file(const char *filename, string data){
    std::ofstream outfile(filename);
    outfile << data;
    outfile.close();
}


void create_fkey(string keyfile, string p_filename)
{
    string base_path = "./";
#ifdef DEBUG
    base_path =  __FILE__ ;
    base_path = base_path.replace(base_path.find("/authorize/authorize/authorize.cpp"), sizeof("/authorize/authorize/authorize.cpp")-1, "/");
#endif
    
    string key_path = base_path + keyfile;
    string file_path = base_path + p_filename;
    string fkey_path = base_path + "f" + keyfile;
    string sfile_path = base_path + "s"+  p_filename;

    
    string key = get_file_contents(key_path.c_str());
    //std::cout << "-key: " << key << endl;
    
    string filename = get_file_contents(file_path.c_str());
    string filename2;
    //cout << "filename " << filename << endl;
    
    
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
    save_file(sfile_path.c_str(), filename2);

    //pad fkey for same as key
    string fkey = key;
    string pad_fname = key;
    float key_len = strlen(key.c_str());
    
    
    
    int i =0;
    for (int x = 0; x < key_len; x ++ ) {
        pad_fname[x] = filename2[i];
        i++;
        if ( i >= strlen(filename2.c_str())){
            i=0;
        }
    }
    
    
    //make fkey
    for(int x=0; x<key_len; x++)
    {
        fkey[x]=pad_fname[x]^key[x];
    }
    
    
    string final_key;
    try
    {
        StringSource(fkey, true,
                     new HexEncoder(
                                    new StringSink(final_key)
                                    ) // HexEncoder
                     );
    }
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    save_file(fkey_path.c_str(), final_key);

}


int main(int argc, char * argv[])
{
    //check the arguments
    if (argc < 3) {
        std::cerr <<"Usage: ./authorize key.txt	filename.txt   " << endl;
        return 1;
    }
    
   
    string keyarg = argv[1];
    string filearg = argv[2];

    create_fkey(keyarg,filearg);
    cout << "AUTHORIZED !!"<<endl;
    return 0;
}

