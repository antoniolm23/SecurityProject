#include "util.h"
#include "key.h"
#include "steganography.h"

class Client{
    
    //socket of the client
    int cliSock;
    //address of the client
    sockaddr_in cliAddr;
    //name of the client
    string name;
    
    //eventually name of the file
    string fileName;
    
    bool StegoMode;
    encryptionMode mode;
    
    //file descriptors to be used in the select
    int fdmax;
    fd_set master, read_fds;
    nonceType cNonce;
    
    Key k;
    steno s;
    //tells the client wether if he has to wait a replay or not
    bool waitFile;
    //part related to the server
    sockaddr servAddr;
    
public:
    
    //constructor
    Client(int, const char*, const char* );
    
    //send the message to the server
    bool sendServMsg(unsigned char*, unsigned int, int = 0);
    //receive message from the server
    unsigned char* recvServMsg(unsigned int*);
    
    //securityProtocol
    //bool securityProtocol();
    
    //receive events from the outside world 
    void receiveEvents();
    
    void parseRecMessage(unsigned char* ,unsigned int);
    
    bool protocol(unsigned char*,unsigned int);
    void parseKeyCommand(char);
    void displayHelp();
    
    //destroyer
    ~Client();
    
};