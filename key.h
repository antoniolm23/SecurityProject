#include "util.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

/* 
 * This file is related to the generation and management of keys
 * NOTE: 
 * Secret is the word used to define symmetric encryption
 * Private and public are the couples used for asymmetric encryption
 */
class Key{
    //file in which there's the key
    //string secretKey;
    EVP_CIPHER_CTX* ctx;
    
    //allocation and preparation of the context
    void contextDecryptAlloc(const char* = 0);
    void contextEncryptAlloc(const char* = 0);
public:
    //constructor (generates the key)
    Key();
    
    void secretKeyGenerator();
    
    //encrypt and decrypt by means of SECRET KEY
    unsigned char* secretDecrypt(const unsigned char*,unsigned int*, const char* = 0);
    unsigned char* secretEncrypt(const unsigned char*,unsigned int*, const char* = 0);
    
    //HASH FUNCTIONS
    unsigned char* generateHash(unsigned char*, unsigned int*);
    bool compareHash(unsigned char*, unsigned int* );
    
    //ASYMMETRIC ENCRYPTION
    void asymmetricKeyGenerator();
    unsigned char* asymmetricDecrypt(const char*, const unsigned char*, unsigned int*);
    unsigned char* asymmetricEncrypt(const char*, const unsigned char*, unsigned int*);
};