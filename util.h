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

using namespace std;

/* 
 * describes if we want an encryption and what kind of encryption we want
 */
enum encryptionMode  {None, Symmetric, Asymmetric};

/*
 * struct that represents a client:
 * name of him, his associated socket and address
 */
struct clientInfo{
    
    string Name;    //name of the client
    sockaddr * clientAddr; //address of the client
    int clientSock; //socket of the client
    int protoStep;  //step of the protocol
    int expMsgLen;  //expected message len
};

//BEGIN UTILITIES FUNCTION USEFUL IN THE CLEAR
/* 
 * message structure:
 * length of the message, text of the message
 */
struct message{
    int len;
    char* text;
};
//message management (very useful when all runs in the clear)
message receiveMessage(int, sockaddr* = 0);
bool sendMessage(int, message, sockaddr* = 0);

//END UTILITIES FUNCTIONS USEFUL IN THE CLEAR

//BEGIN CRYPTO UTILITIES FUNCTIONS

//file management for the key
unsigned char* readKeyFile(const char*, int);

//file management
void writeFile(const char*, unsigned char*, int);
char* readFile(const char*, int*);

//printbyte
void printByte(unsigned char*, int);

/* 
 * redefinition of the basic primtives of send and receive 
 * (useful when we need to deal with the exchange of secret messages)
 */
bool sendBuffer(int,unsigned char*,unsigned int, sockaddr* = 0);
bool receiveBuffer(int,unsigned char*,unsigned int, sockaddr* = 0);

//END CRYPTO UTILITIES FUNCTIONS