//
//  main.cpp
//  authorize
//
//  Created by Anshul Vikram Pandey on 11/30/14.
//  Copyright (c) 2014 Anshul Vikram Pandey. All rights reserved.
//




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
    throw(errno);
}

int hexCharToInt(char a){
    if(a>='0' && a<='9')
        return(a-48);
    else if(a>='A' && a<='Z')
        return(a-55);
    else
        return(a-87);
}

std::string xorTwoHexStrings(string str1, string str2){
    std::stringstream XORString;
    for(int i=0;i<str2.length();i++){
        XORString << hex << (hexCharToInt(str1[i])^hexCharToInt(str2[i]));
    }
    return XORString.str();
}


/*
string xnorTwoHexStrings(string str1, string str2){
    std::stringstream XNORString;
    for(int i=0;i<str2.length();i++){
        XNORString << hex << (~(hexCharToInt(str1[i])^hexCharToInt(str2[i])));
    }
    return XNORString.str();
}

 */

void create_fk(string keyfile, string filename)
{
    //cout << "entered function";
    // cout << keyfile.c_str() << filename;
    string hexFname;
    
    string base_path = "/Users/avp/Dropbox/Projects/Cryptography/NewProject2/proj2/";
    //string base_path = "/Users/amd/code/cpp/proj2/";
    
    string key_path = base_path + keyfile;
    string file_path = base_path + filename;
    
    
    string key = get_file_contents(key_path.c_str());
    std::cout << key;
    
    string fname = get_file_contents(file_path.c_str());
    std::cout << fname;
    
    
    try
    {
        StringSource(fname, true,
                     new HexEncoder(
                                    new StringSink(hexFname)
                                    ) // HexEncoder
                     );
    }
    
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    std::ofstream fn3(base_path+"sfilename.txt");
    fn3 << hexFname << std::endl;
    fn3.close();
    
    
    cout << hexFname;
    std::ofstream outfile(base_path+"fkey.txt");
    outfile << hexFname + key << std::endl;
    outfile.close();
    
    
    //const byte* keybyte = (const byte*) key.data();
    //const byte* fnamebyte = (const byte*) hexFname.data();
    
    
    

}


int main(int argc, char * argv[])
{

    std::string keyfile, filename;
    //  cout << argv[1];
   // keyfile = filepath + argv[1];
    //filename = filepath + argv[2];
    // cout << keyfile;
    // cout << filename;
    create_fk("key.txt","file.txt");
    
    return 0;
}

