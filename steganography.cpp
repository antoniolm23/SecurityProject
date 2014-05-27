#include "steganography.h"

/*
 * Function that implements the Least Significant Bit steganography
 * @params:
 *          message: the message to embed in the image
 *          size: (INOUT) at first the size of the message, 
 *                      then the size of the image with the message embedded
 * @return: the image with the hidden message
 * NOTE: the header of the bitmap file is 54 bits 
 * NOTE: allocated virtual memory
 * TODO: allow shift of more than one position
 */
unsigned char* steno::LSBSteno(unsigned char* message, unsigned int* size) {
    
    char* image;
    unsigned int len;
    int shift = 1;
    const unsigned char constantAnd = 0xfe; //constant used int the and
    image = readFile("image.bmp", &len);
    
    int sizeOfInt = sizeof(int);
    
    //check if there is enough space in the image to put the message and its length
    while( ((*size + sizeOfInt) * 8) > (len * shift)) {
        
        return NULL;
        
    }
    
    /* 
     * now the first thing to do is to skip the header of the image, we treat 
     * only .bmp images since we have the codec of the colours, we assume 24 bit
     * used for pixel 
     */
    image += 54;
    int ptr = 0; //used to keep track of the point we reached in the image
    
    int sizeIntBit = sizeOfInt * 8;
    int tmpSize = *size;
    //write the size of the message
    for(int i = 0; i < sizeIntBit ; i += shift) {
        
        image[i] &= constantAnd;
        int tmp = tmpSize & 0x01;
        tmpSize = tmpSize >> shift;
        //cout << tmpSize<<" "<< tmp<<endl;
        image[i] |= tmp;
        ptr ++;
        
    }
    
    //now we can write the message to hide inside the image
    for(unsigned int i = 0; i < *size; i++) {
        
        //write a byte into 8 bytes of an image
        unsigned char tmpChar = message[i];
        for(int j = 0; j < 8; j++) {
            
            image[ptr] &= constantAnd;
            int tmp = tmpChar & 0x01;
            tmpChar = tmpChar >> shift;
            image[ptr] |= tmp;
            ptr++;
            
        }
        
    }
    
    *size = len;
    //cout<<message<<endl;
    //writeFile("hello.bmp", (unsigned char*)image - 54, len);
    return (unsigned char*)(image - 54);
    
}

/* 
 * Read a message hidden inside an image
 * @params:
 *          buffer: the buffer from which extract the message
 *          size: (OUT) used to return the size of the message
 * @return:
 *          the message read from the image
 * NOTE: 54 bit is the size of the bitmap header
 * NOTE: allocated memory remember to free it
 */
unsigned char* steno::readMessage(unsigned char* buffer,unsigned int* size) {
    
    unsigned char* stenoImage = buffer;
    const unsigned char andBit = 0x01;
    
    stenoImage += 54;
    int ptr = 0;
    
    int sizeIntBit = sizeof(int) * 8;
    unsigned int tmpLen = 0;
    
    //read the length of the message previously written
    for(int i = 0; i < sizeIntBit; i++) {
        
        unsigned int leastBit = stenoImage[i] & andBit;
        tmpLen |= (leastBit << i);
        ptr++;
        
    }
    
    cout<<tmpLen<<endl;
    
    *size = tmpLen;
    unsigned char* message = new unsigned char[tmpLen];
    memset(message, 0, tmpLen);
    
    //read the hidden message present in the image
    for(unsigned int i = 0; i< tmpLen; i++) {
        
        for(int j = 0; j < 8; j++) {
            
            unsigned char tmp = stenoImage[ptr] & andBit;
            message[i] |= (tmp << j);
            ptr++;
            
        }
        
    }
    
    //printByte(message, tmpLen);
    //cout<<message<<endl;
    //writeFile("messagehidden.png", (unsigned char*)message,  tmpLen);
    return message;
}

