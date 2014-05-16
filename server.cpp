#include "server.h"
#include "key.h"

/* 
 * Constructor of the class server
 * @params: 
 *          ip address of the server
 *          port on which the server accepts connections 
 */
Server::Server(const char* host, int port) {
    
    //creates the socket
    servSock = socket(AF_INET, SOCK_STREAM, 0);
    
    //filling the sockaddr_in structure
    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family=AF_INET;
    servAddr.sin_port=htons(port);
    hostent* he;
    if(inet_aton(host, &servAddr.sin_addr)!=0) {
        he=gethostbyname(host);
        if(!he) {
            cerr<<"Can't solve server name"<<host<<" \n";
            exit(1);
        }
        servAddr.sin_addr =* (struct in_addr*) he->h_addr;
    }

    //changing the socket in listen type
    if(bind(servSock, (struct sockaddr*) &servAddr, sizeof(servAddr))<0) {
        cerr<<"Error in binding of the socket \n";
        exit(-1);
    }
    if(listen(servSock, 0)<0) {
        cerr<<"Error in listening of the socket\n";
        exit(-1);
    }

    //preparing the file descriptors
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(servSock, &master);
    fdmax=servSock;

    //initialize the string
    name = string(host);
    
    clientList = list<clientInfo>();
    
    cout<<"server connected at port "<<port<<" host "<<host<<endl;
    
    
}

/* 
 * Search in the list the client to which belongs the socket
 * @params:
 *          s: socket number
 * @returns
 *          Client if present otherwise 0
 */
clientInfo Server::searchListSocket(int sock) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    clientInfo t;
    
    for(;p!=q; p++) {

        if(p->clientSock == sock) {
            t.Name = p->Name;
            t.clientAddr = p -> clientAddr;
            t.clientSock = p -> clientSock;
            t.protoStep = p -> protoStep;
            t.expMsgLen = p -> expMsgLen;
            return t;
        }
    }
    
    return t;
    
}

/* 
 * Receive a message from a client
 * @params
 *          sock: socket of the client to who the server is sending the message
 * @returns
 *          the message received
 */
bool Server::RecvClientMsg(int sock, unsigned char* msg, unsigned int len) {
    
    return receiveBuffer(sock, msg, len);
    
}

/* 
 * Send a client a message
 * @params
 *          sock: socket of the client to who the server is sending
 *          msg: the effective message
 * @returns
 *          how the send went 
 */
bool Server::SendClientMsg(int sock, unsigned char* msg, unsigned int len) {
    
    return sendBuffer(sock, msg, len);
}

/* 
 * ADD something
 * Accept a new connection by a client and add it in the list if it's not
 * already present in the list
 */
void Server::acceptConnection() {
    
    clientInfo arrivedClient;
    int len;
    
    //allocate the socket for a new client
    arrivedClient.clientSock = accept(servSock, (sockaddr*) 
        &arrivedClient.clientAddr, (socklen_t*)&len);
    
    if(arrivedClient.clientSock > servSock)
        fdmax = arrivedClient.clientSock;
    
    FD_SET(arrivedClient.clientSock, &master);
    arrivedClient.Name = string("\0");
    //this means that the login has to be done
    arrivedClient.protoStep = TODOLOGIN;
    arrivedClient.expMsgLen = 0;
    
    //insert the client in the list (last action to do)
    clientList.push_back(arrivedClient);
    
    cout<<"Arrived client "<<arrivedClient.expMsgLen<<endl;
    
}

/* 
 * Changes the public and the private key of the server
 */
void Server::changeKey(){

}

/* 
 * A simple help display on stdout
 */
void Server::displayHelp(){
    
    cout<<"Possible commands are:\n"
    <<"'h' displayHelp\n"
    <<"'k' change public and private key\n";
    
}


/* 
 * NOTE: possible commands:
 * 'h': help
 * 'k': changeKeys
 */
void Server::parseKeyCommand(){
    
    char cmd;
    cin>>cmd;
    
    //now we have the command in the cmd variable
    switch(cmd) {
        case 'h':
            displayHelp();
            break;
        case 'k':
            changeKey();
            break;
        case 'q':
            exit(1);
        default:
            break;
    }
    
}

/*
 * Once decrypted the message, send the requested file if possible otherwise
 * return an error message 
 * @params:
 *          text: is the command + filename
 *          size: (INOUT) at first the size of the message
 *                      then the size of the encrypted file
 * @return
 *          the message to send to the client
 * NOTE: the allocated virtual memory for msg.text is deleted
 */
char* EncryptFile(char* text, int* len) {
    
    char* defBuffer, *encText;
    //the client sends the filename after the command (6 characters)
    //jumps after the command
    text[*len] = '\0';
    *len -= 6;
    
    //cout<<msg.text<<endl;
    int size = 0;
    //read the content of a file
    char* buffer = readFile(&text[6], &size);
    
    //if a buffer is empty then send the client an error message
    if(buffer == NULL) {
        return NULL;
    }
    
    //otherwise compute hash, encrypt the buffer and send it to the client
    else {
        Key k = Key();
		
        //BEGIN HASH COMPUTATION
        int tmpSize = size;
        unsigned char* hashBuf = k.generateHash(buffer, &size);
        size = size + tmpSize; //size of file plus its hash
        defBuffer = new char[(size)];
        //copy at the beginning the buffer
        memcpy(defBuffer, buffer, tmpSize);
        //now copy the hash computed
        memcpy(&defBuffer[tmpSize], (const char*)hashBuf, (size - tmpSize));
        delete(buffer);
        //END HASH COMPUTATION
		
        //encrypt by means of the secret key
        encText = (char*)k.secretEncrypt((unsigned char*)defBuffer, &size);
        *len = size;
    }
    delete(defBuffer);
    return encText;
    
}

/* 
 * Parse the received message and decide the action to perform
 * The decision is based upon the length of the message, if it's
 * length is equal to the one of the public key then this is the 
 * beginning of the protocol, otherwise check if the client has 
 * reached some point of the protocol.  
 * @params:
 *          size: dimension of the message
 * NOTE: the message is effectively received in this function
 */
/* NOTE: command issued by the client is 6 bytes long for semplicity*/
void Server::parseReceivedMessage(int sock) {
    
    bool actionPerformed = false;
    bool encryption = false;
    
    //search the client structure in which we have some infos
    clientInfo cl = searchListSocket(sock);
    int len;
    char* text;
    //this means asymmetric encrypted message
    if(cl.expMsgLen == 0 || cl.expMsgLen == messageLen) {
        
        encryption = true;
        len = messageLen;
        unsigned char msg[messageLen];
        bool recResult = RecvClientMsg(sock, msg, len);
        //in case the client doesn't send what the server expects NO REPLY
        if(recResult == false) {
            cerr<<"wrong message received"<<endl;
            return;
        }
        
        //decrypt the received message
        Key k = Key();
        unsigned char* decMessage = k.asymmetricDecrypt("server/priv.pem", 
            msg, &len);
        text = (char*)decMessage;
        printByte((unsigned char*)text, len);
    }
    
    if(cl.protoStep == TODOLOGIN) {
        //if the client has issued a login command than the server fills it 
        if(strncmp("login ", text, 6) == 0) {
            
            actionPerformed = true;
            //the client sends its name along with the command
            //jumps after the command
            text += 6; 
            len -= 6;
            cl.Name = string(text);
            
            list<clientInfo>::iterator p = clientList.begin();
            list<clientInfo>::iterator q = clientList.end();
            
            //scan the list and update the right client
            for(; p!=q; p++) {
                if(p->clientSock == cl.clientSock) {
                    p->Name = cl.Name;
                    p->protoStep = DONELOGIN;
                }
            }
            
            cout<<"Client Name: "<<cl.Name<<endl;
            
        }
    }
    
    //check if we have received a file request
    if(strncmp("fireq ", text, 6) == 0) {
        
        actionPerformed = true;
        char* encText = EncryptFile(text, &len);
        bool resSend = false;
        int i = 0;
        //send the message until it's correct sent 
        //NOTE to avoid infinite loops at max 4 times
        while(resSend == false || i == 4) {
            resSend = sendBuffer(cl.clientSock, 
                                  (unsigned char*)encText, (unsigned int)len);
            i++;
        }
        delete (encText);
        //delete(msg.text);
    }
    
    //this means we have to decrypt a message by means of the symmetric key
    if(!actionPerformed && !encryption) {
        
        len = cl.expMsgLen;
        unsigned char* buf = new unsigned char[len];
        bool recResult = RecvClientMsg(cl.clientSock, buf, len);
        if(recResult == false)
            return;
        Key k = Key();
        
        //printByte((unsigned char*)buf, len);
        
        //first decrypt the message
        unsigned char* decBuf = 
            k.secretDecrypt((const unsigned char*)buf, &len);
        //cout<<debuf<<" "<<len<<endl;
        
        //delete all used data structures
        delete(buf);
        
        //TODO add parsing
        //cout<<"second print: "<<msg1.text<<endl;
        
    }
    
}

/* 
 * Handles the receiving of events from the outside world
 */
void Server::receiveEvents() {
    
    //infinite loop to accept events
    while(1) {
        
        //cout<<"hello"<<endl;
        
        read_fds=master;
        if(select(fdmax+1, &read_fds, NULL, NULL, NULL)==-1) {
            cerr<<" error in the select"<<name<<" \n";
            exit(1);
        }
        
        /* 
         * roll all the file descriptors and
         * checks if the file descriptor has been set
         */ 
        for(int i=0; i<=fdmax; i++) {
            
            //cout<<"for cycle "<<i<<endl;
            
            //this means keyboard event
            if(FD_ISSET(0, &read_fds)) 
                parseKeyCommand();
            if(FD_ISSET(i, &read_fds)) {
                
                //checks if there's a new connections
                if(i == servSock) {
                    //cout<<"new connection"<<endl;
                    acceptConnection();
                }
                
                //this means a receiving message
                //NOTE: i > 2 to avoid the stderr and the stdout 
                if(i > 2 && i != servSock) {
                    parseReceivedMessage(i);
                }
            break;
            }
        }
    }
}

/* 
 * Destroyer of the server
 */
Server::~Server(){
    clientList.clear();
}

