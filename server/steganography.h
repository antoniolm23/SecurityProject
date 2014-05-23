#include "util.h"

/* 
 * Stenography is a tecnique that allows us to hide a message into an image
 * many tecniques have been proposed, for sake of simplicity I will implement
 * the LSB one, The first byte after the header will provide the dimension of
 * the message, so that everything is self-contained, of course this pose a 
 * serious concern since the message is in the clear and an adversary may 
 * play the role of the server, here we will use that also the assumption that
 * the hash is included in the message and further that the server applies 
 * watermarking to the portion of the image where there is the message
 * (not implemented)
 */
class steno{
    
public:
    
    steno() {};
    
    //Least Significant Bit Steganography
    unsigned char* LSBSteno(unsigned char*,unsigned int*); 
    unsigned char* readMessage(unsigned char*, unsigned int*);
};