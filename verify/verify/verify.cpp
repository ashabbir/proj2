//  Created by Ahmed Shabbir & Anshul Pandey on 12/5/14.
//  Copyright (c) 2014 CRYPTO. All rights reserved.


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
#include "pssr.h"


using namespace CryptoPP;


int main(int argc, char* argv[])
{
    
    //get the file dir structure
    string base_path = "./";
#ifdef DEBUG
    base_path =  __FILE__ ;
    base_path = base_path.replace(base_path.find("/verify/verify/verify"),
                                  sizeof("/verify/verify/verify.cpp")-1, "/");
#endif
    
    
    
    string public_key_path = base_path + "pub_key.txt";
    string message_path = base_path + "message.txt";
    string sign_path = base_path + "signature.txt";
    string result_path = base_path + "sign_result.txt";
    
    

    try {
        
        // Generate keys
        AutoSeededRandomPool rng;
        
        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);
        
        
        // load public key Example taken from wiki crypopp
        std::ifstream ifs1(public_key_path);
        std::string content_public((std::istreambuf_iterator<char>(ifs1)),
                                   (std::istreambuf_iterator<char>()));
        
        RSA::PublicKey publickey;
        StringSource f2(content_public, true, new HexDecoder);
        publickey.Load(f2);
        
        
        
        //load msg
        std::ifstream ifs2(message_path);
        std::string content_message((std::istreambuf_iterator<char>(ifs2)),
                                    (std::istreambuf_iterator<char>()));
        
        string message = content_message, signature, recovered;
        
        
        
        //load signature
        std::ifstream in(sign_path);
        std::string content((std::istreambuf_iterator<char>(in)),
                            (std::istreambuf_iterator<char>()));
        
        
        
        
        string decoded;
        StringSource(content, true,
                     new HexDecoder(
                                    new StringSink(decoded)
                                    ) // HexEncoder
                     ); // StringSource

        
        
        // Verify and Recover (example from wiki cryptopp)
        RSASS<PSSR, SHA1>::Verifier verifier(publickey);
        
        StringSource(decoded, true,
                     new SignatureVerificationFilter(
                                                     verifier,
                                                     new StringSink(recovered),
                                                     SignatureVerificationFilter::THROW_EXCEPTION |
                                                     SignatureVerificationFilter::PUT_MESSAGE
                                                     ) // SignatureVerificationFilter
                     ); // StringSource
    
        if (message == recovered) {
        string a = "YES";
        std::ofstream out(result_path);
        out << a;
        out.close();
        cout << "Message verified"<< endl;
        } else {
            string a = "NO";
            std::ofstream out(result_path);
            out << a;
            out.close();
            cout << "Message NOT verified"<< endl;

        }
        
    } // try
    
    catch (CryptoPP::Exception&e)
    {
        cout << "ERROR !!"<< endl;
        string a = "NO";
        std::ofstream out(result_path);
        out << a;

        
    }
    return 0;
}


