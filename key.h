#include "util.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define keySize 16
#define pubBits 1024
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
    void contextDecryptAlloc();
    void contextEncryptAlloc();
public:
    //constructor (generates the key)
    Key();
    
    void secretKeyGenerator();
    
    //encrypt and decrypt by means of SECRET KEY
    unsigned char* secretDecrypt(const unsigned char*, int*);
    unsigned char* secretEncrypt(const unsigned char*, int*);
    
    //HASH FUNCTIONS
    unsigned char* generateHash(char*, int*);
    bool compareHash(char*, int* );
    
    //ASYMMETRIC ENCRYPTION
    void asymmetricKeyGenerator();
    unsigned char* asymmetricDecrypt(const char*, const unsigned char*, int*);
    unsigned char* asymmetricEncrypt(const char*, const unsigned char*, int*);
};