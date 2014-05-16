#include "util.h"

class Client{
    
    //socket of the client
    int cliSock;
    //address of the client
    sockaddr_in cliAddr;
    //name of the client
    string name;
    
    //eventually name of the file
    string fileName;
    
    encryptionMode mode;
    
    //file descriptors to be used in the select
    int fdmax;
    fd_set master, read_fds;
    
    //tells the client wether if he has to wait a replay or not
    bool waitFile;
    
    //part related to the server
    sockaddr servAddr;
    
public:
    
    //constructor
    Client(int, const char*, const char* );
    
    //send the message to the server
    bool sendServMsg(message);
    //receive message from the server
    message recvServMsg(int);
    
    //securityProtocol
    bool securityProtocol();
    
    //receive events from the outside world 
    void receiveEvents();
    
    void parseRecMessage(message);
    
    void parseKeyCommand(char);
    void displayHelp();
    
    //destroyer
    ~Client();
    
};