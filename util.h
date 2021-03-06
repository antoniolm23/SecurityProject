#pragma once
#include <iostream>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/types.h>
#include <string>
#include <netinet/in.h>
#include <list>
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

#define TODOLOGIN -1
#define DONELOGIN 0
#define KEYEXCHANGED 3
#define NONCEBEGIN 0xff34
#define keySize 16
#define pubBits 1024
#define hashLen 20 //use of sha1 so 20 bytes
#define maxClientName 30
#define sizeCommand 6

using namespace std;

/* 
 * describes if we want an encryption and what kind of encryption we want
 */
enum encryptionMode  {None, Symmetric, Asymmetric};

//define the type of the nonce to have more flexibility in the whole program
typedef unsigned int nonceType;

/*
 * struct that represents a client:
 * name of him, his associated socket and address
 */
struct clientInfo{
    
    string Name;            //name of the client
    sockaddr * clientAddr;  //address of the client
    int clientSock;         //socket of the client
    int protoStep;          //step of the protocol
    int expMsgLen;          //expected message len
    encryptionMode encrypt; //use encryption?
    bool sMode;             //steganography mode
    unsigned char secret[hashLen];  //hash of the secret of the client
    
};

//client message sent to the server in the 2nd step of the protocol
struct cliMessage {
    
    int nonceClient;
    int nonceServer;
    unsigned char key[keySize];
    unsigned char secret[hashLen];
    //char* padding;
    
};

//BEGIN CRYPTO UTILITIES FUNCTIONS

//file management for the key
unsigned char* readKeyFile(const char*, int);

//file management
bool writeFile(const char*, unsigned char*, unsigned int);
char* readFile(const char*, unsigned int*);

//printbyte
void printByte(unsigned char*, int);

/* 
 * redefinition of the basic primtives of send and receive 
 * (useful when we need to deal with the exchange of secret messages)
 */
bool sendBuffer(int,unsigned char*,unsigned int, sockaddr* = 0);
unsigned char* receiveBuffer(int, unsigned int*, sockaddr* = 0);

//END CRYPTO UTILITIES FUNCTIONS

//function to generate a random nonce
nonceType generateNonce();
