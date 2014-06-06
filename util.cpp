#include "util.h"
#include <openssl/rand.h>

/**
 * Write a file with a buffer of a fixed length
 * @params
 *          filename: name of the file
 *          buffer: buffer to write
 *          dim: dimension of the buffer
 * @return
 *          the outcome of the write
 */
bool writeFile(const char* filename, unsigned char* buffer,unsigned int dim) {
    
    FILE* f = fopen(filename, "w");
    
    if( f == NULL) {
        cerr<<"file not opened"<<endl;
        return false;
    }
    
    //effective write on the file
    fwrite(buffer, 1, dim, f);
    fclose(f);
    return true;
    
}

/** 
 * Read the content of the file and put in into a string that will be returned
 * @params
 *          filename: the name of the file
 *          n: the length to be read if known in advance
 * @return
 *          string: the content of the file
 */
unsigned char* readKeyFile(const char* filename, int n) {
    
    unsigned char* buffer = new unsigned char[n];
    FILE* f = fopen(filename, "r");
    
    if( f == NULL) {
        cerr<<"file not opened"<<endl;
        return NULL;
    }
    
    fread(buffer, 1, n, f);
    //buffer[n] ='\0';
    fclose(f);
    
    return buffer;
    
}

/** 
 * Print the string byte by byte
 * @params:
 *          tmp: the buffer to print
 *          len: the length of the string
 */
void printByte(unsigned char* tmp, int len) {
    for(int i=0; i<len; i++)
        fprintf(stdout, "%i ", tmp[i]);
    cout<<endl;
}

/** 
 * Read a whole file
 * @parmas:
 *          namefile: the name of the file
 *          size: OUT parameter used to return the dimension of the buffer
 * @returns:
 *          buffer that contains the file 
 */
char* readFile(const char* name, unsigned int* size) {
    
    unsigned int fsize;
    char* fbuffer;
    //open the file a first time to check the length of it
    FILE* fp=fopen(name, "r");
    
    if( fp == NULL) {
        cerr<<"file not opened"<<endl;
        return NULL;
    }
    
    fseek(fp, 0, SEEK_END);           //reach the end of it
    fsize = ftell(fp);
    fclose(fp);
    
    //open the file to read it and put its content into a buffer
    fp=fopen(name, "r");
    
    if( fp == NULL) {
        cerr<<"file not opened"<<endl;
        return NULL;
    }
    
    fbuffer=new char[fsize];
    //copy of the buffer
    fread(fbuffer, 1, fsize, fp);
    *size = fsize;
    return fbuffer;
    
}

/*****************************************************************************
 * REDEFINITION OF THE BASIC SEND AND RECEIVE PRIMITIVES
 *****************************************************************************/
/** 
 * Redefinition of the sendto function used in C in order to provide less
 * arguments
 * @params:
 *          sock: file descriptor on which send the buffer
 *          text: pointer to the buffer to send
 *          len: length of the buffer
 *          addr: (OPTIONAL) IP address
 * @return
 *          true if all the data are sent, false otherwise
 */
bool sendBuffer(int sock, unsigned char* text, unsigned int len, 
                sockaddr* addr) {
    
    //checking passed parameters
    if(sock < 0 || len == 0)
        return false;
    
    unsigned int size = len;
    
    /*//at first send the size
    if(sendto(sock, (void*)&size, sizeof(unsigned int), 0, addr, 
        sizeof(sockaddr)) != sizeof(unsigned int)) {
        
        return false;
        
    }*/
    
    //now send the message
    size = sendto(sock, text, len, 0, addr, sizeof(sockaddr));
    
    //cout<<"printing:";
    //printByte(text, len);
    //check the amount of sent data
    if(len == size) 
        return true;
    else
        return false;
    
}

/** 
 * Redefinition of the recvfrom function
 * @params:
 *          sock: file descriptor on which we do the receive
 *          size: (OUT) the dimension of the received buffer
 *          addr: (OPTIONAL) IP address from which we receive the data
 * @return:
 *          the received buffer
 * NOTE: allocated memory for buf
 */
unsigned char* receiveBuffer(int sock, unsigned int* size, sockaddr* addr){
    
    //checking parameters
    if(sock < 0)
        return NULL;
    
    socklen_t sizeSockAddr = sizeof(sockaddr);
    unsigned char* tmpBuf;
    
    /*//receive the dimension of the message
    if(recvfrom(sock, (void*)&len, sizeof(int), 0, addr, 
        &sizeSockAddr) != sizeof(unsigned int)) {
        
        return NULL; //first message received wrong
        
    }
    
    *size = len;
    */
    tmpBuf = new unsigned char[*size];
    
    //effective receive
    unsigned int expected = recvfrom(sock, (void*)tmpBuf, *size, 
                            MSG_WAITALL, addr, &sizeSockAddr);
    
    //check the amount of received data
    if(expected == *size) {
        //cout<<"printing the buffer: ";
        //printByte(tmpBuf, *size);
        return tmpBuf;
    }
    else
        return NULL;

}

//generates a random nonce
nonceType generateNonce() {
    
    nonceType nonce;
    RAND_bytes((unsigned char*)&nonce, sizeof(nonceType));
    return nonce;
    
}