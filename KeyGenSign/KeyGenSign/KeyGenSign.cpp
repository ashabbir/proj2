//
//  Created by Ahmed Shabbir on 12/5/14.
//  Copyright (c) 2014 CRYPTO. All rights reserved.
//

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <sstream>
#include <istream>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using namespace std;

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


#include "rsa.h"


void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void SaveHex(const string& filename, const BufferedTransformation& bt);

int main(int argc, char** argv)
{
    
    string base_path = "./";
#ifdef DEBUG
    base_path =  __FILE__ ;
    base_path = base_path.replace(base_path.find("/KeyGenSign/KeyGenSign/KeyGenSign.cpp"),
                                  sizeof("/KeyGenSign/KeyGenSign/KeyGenSign.cpp")-1, "/");
#endif
    
    AutoSeededRandomPool prng;
    string public_key_hex;
    string priavte_key_hex;
    
    //save the key file in hex format
    string public_key_path = base_path + "signpublickey.txt";
    string private_key_path = base_path + "signsecretkey.txt";
    string message_path = base_path + "message.txt";
   
    // http://www.cryptopp.com/docs/ref/class_auto_seeded_random_pool.html
    AutoSeededRandomPool rnd;
    
    try
    {
        
        // http://www.cryptopp.com/docs/ref/rsa_8h.html
        RSA::PrivateKey rsaPrivate;
        rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);
        
        RSA::PublicKey rsaPublic(rsaPrivate);
        
        //example taken from wiki cryptopp
        SaveHexPrivateKey(private_key_path, rsaPrivate);
        SaveHexPublicKey(public_key_path, rsaPublic);
        
        std::ifstream ifs1(public_key_path);
        std::string content_public((std::istreambuf_iterator<char>(ifs1)),
                                   (std::istreambuf_iterator<char>()));
        
        string myString = "as7231@nyu.edu";
        istringstream buffer(myString);
        uint64_t value;
        buffer >> std::hex >> value;
        
        std::stringstream sstm;
        sstm << content_public << value;
        string result = sstm.str();
        
        std::ofstream out(message_path);
        out << result;
        out.close();
        
        
        cout << "GENERATED !!" << endl;
        
        
    }
    
    catch (CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        return -2;
    }
    
    catch (std::exception& e)
    {
        cerr << e.what() << endl;
        return -1;
    }
    return 0;
}


void Save(const string& filename, const BufferedTransformation& bt)
{
    // http://www.cryptopp.com/docs/ref/class_file_sink.html
    FileSink file(filename.c_str());
    
    bt.CopyTo(file);
    file.MessageEnd();
}



void SaveHexPrivateKey(const string& filename, const PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    
    SaveHex(filename, queue);
}

void SaveHexPublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    
    SaveHex(filename, queue);
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
    HexEncoder encoder;
    
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    
    Save(filename, encoder);
}