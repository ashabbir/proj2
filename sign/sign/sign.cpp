//  Created by Ahmed Shabbir on 12/5/14.
//  Copyright (c) 2014 CRYPTO. All rights reserved.
//



#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <fstream>
#include <cerrno>
#include <iostream>
#include <string>
//#include <conio.h>
using namespace std;
#include "integer.h"
using CryptoPP::Integer;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "pssr.h"
using CryptoPP::PSSR;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;


#include "cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::InvertibleRSAFunction;

#include "rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSASS;
using CryptoPP::RSA;

#include "filters.h"
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "sha.h"
using CryptoPP::SHA1;

#include <string>
using std::string;

#include "queue.h"
using CryptoPP::ByteQueue;





int main(int argc, char* argv[])
{
    string base_path = "./";
#ifdef DEBUG
    base_path =  __FILE__ ;
    base_path = base_path.replace(base_path.find("/sign/sign/sign.cpp"),
                                  sizeof("/sign/sign/sign.cpp")-1, "/");
#endif
    
    
    
    string secret_key_path = base_path + "priv_key.txt";
    string message_path = base_path + "message.txt";
    string sign_path = base_path + "signature.txt";
    

    try {
        

        // Generate keys
        AutoSeededRandomPool rng;
        
        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);
        
        //load key
        std::ifstream ifs1(secret_key_path);
        std::string content_secret((std::istreambuf_iterator<char>(ifs1)),
                                   (std::istreambuf_iterator<char>()));
        
        RSA::PrivateKey secretkey;
        StringSource f2(content_secret, true, new HexDecoder);
        secretkey.Load(f2);
        
        std::ifstream ifs2(message_path);
        std::string content_message((std::istreambuf_iterator<char>(ifs2)),
                                    (std::istreambuf_iterator<char>()));
        
        string message = content_message, signature, recovered;
        

        // Sign and Encode example from wiki cryptopp
        RSASS<PSSR, SHA1>::Signer signer(secretkey);
        
        StringSource(message, true,
                     new SignerFilter(rng, signer,
                                      new StringSink(signature),
                                      true)
                     ); // StringSource

        
        string encoded;
        encoded.clear();
        
        
        StringSource(signature, true,
                     new HexEncoder(
                                    new StringSink(encoded)
                                    ) // HexEncoder
                     ); // StringSource

        
        
        cout << "SIGNATURE GENERATED !!" << endl;
        std::ofstream out(sign_path);
        out << encoded;
        out.close();
        
    } // try
    
    catch (CryptoPP::Exception&e)
    {
        std::cerr << "Error: " << e.what() << endl;
    }

    return 0;
}

