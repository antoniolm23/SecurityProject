/*
 *This is the server header file, the server is written in C++ and works 
 *on IPv4 only  
*/
#include "util.h"
#include "key.h"
#include "steganography.h"
#define messageLen 128 

class Server {
    
    //string that represents the path to the key
    string keyPath;
    sockaddr_in servAddr;
    //standard socket on which the server will accept connections
    int servSock;
    //path to the resource addressed by the server
    string resPath;
    //file descriptor integers to be managed with the select
    int fdmax;
    fd_set master, read_fds;
    string name;
    bool steganoMode;
    
    Key k;
    steno s;
    
    //list of connected clients
    list<clientInfo> clientList;
    
    nonceType nonce;
    
    //PRIVATE FUNCTIONS
    void parseKeyCommand();
    void changeKey();
    void displayHelp();
    unsigned char* prepareFile(char*, int*);
    
    //functions on the list
    clientInfo searchListSocket(int);
    clientInfo searchListByName(char*);
    void removeClient(int);
    int maxSock();
    int getEncrypt(int);
    void setEncrypt(int , encryptionMode);
    void setSecret(int, unsigned char*, int);
    void setKey(int, unsigned char*);
    const char* getKey(int);
    unsigned char* getSecret(int);
    unsigned char* settleReply(unsigned char*, unsigned int*);
    bool verifyReceivedMsg(int, unsigned char*, unsigned int);
    
public:
    
    Server(const char*, int);
    
    //accept a connection by a client
    void acceptConnection();
    
    /* 
     * handles the receiving of events coming from outside 
     * e.g. keyboard or socket
     */
    void receiveEvents();
    
    //send and receive message to and from a client
    unsigned char* RecvClientMsg(int, unsigned int*);
    bool SendClientMsg(int, unsigned char*, unsigned int);
    
    /*parses the received message in order to take the right decision*/
    void parseReceivedMessage(int, unsigned char*, int);
    
    bool protocol(char*);
    
    //destroyer
    ~Server();
};
