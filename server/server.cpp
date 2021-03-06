#include "server.h"

/** 
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
    
    steganoMode = true;

    //initialize the string
    name = string(host);
    
    clientList = list<clientInfo>();
    
    nonce = NONCEBEGIN;
    k = Key();
    s = steno();
    
    cout<<"server connected at port "<<port<<" host "<<host<<endl;
    
}

/* *****************************************************************************
 * FUNCTIONS THAT OPERATE ON THE LIST
 * ****************************************************************************/

/** 
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
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            t.Name = p -> Name;
            t.clientAddr = p -> clientAddr;
            t.clientSock = p -> clientSock;
            t.protoStep = p -> protoStep;
            t.expMsgLen = p -> expMsgLen;
            t.encrypt = p -> encrypt;
            return t;
        }
    }
    
    return t;
    
}

/** 
 * Search a client in the list basing on its name
 * @params: 
 *          name of the client
 * @return:
 *          clientInfo structure
 */
clientInfo Server::searchListByName(char* client) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    clientInfo t;
    
    for(; p != q; p++) {

        if(strncmp(p -> Name.c_str(), client, p -> Name.length()) == 0) {
            t.Name = p -> Name;
            t.clientAddr = p -> clientAddr;
            t.clientSock = p -> clientSock;
            t.protoStep = p -> protoStep;
            t.expMsgLen = p -> expMsgLen;
            t.encrypt = p -> encrypt;
            return t;
        }
    }
    
    return t;
    
}

/** 
 * gets if the client has already had the key exchange protocol
 * @params:
 *          sock: the socket of the client, useful in the search
 * @return:
 *          returns whether the client has already had the exchange protocol
 */
int Server::getEncrypt(int sock){
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    clientInfo t;
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            
            return p -> encrypt;
            
        }
    }
    
    return false;
    
}

/**
 * sets the encrypt parameter to true
 * @params:
 *          sock: the socket of the client, useful in the search
 *          type: the type of encryption we decided to use
 */
void Server::setEncrypt(int sock, encryptionMode type) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    clientInfo t;
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            
            p -> encrypt = type;
            
        }
    }
    
}

/**
 * Set the shared secret between the client and the server
 * @params:
 *          sock: socket to do the search
 *          secret: the shared secret
 *          size: size of the shared secret
 */
void Server::setSecret(int sock, unsigned char* secret, int size) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    clientInfo t;
    
    for(; p != q; p++) {
        
        //if the socket correspond then do a copy
        if(p -> clientSock == sock)
            memcpy(p -> secret, secret, size);
    }
    
}

/**
 * Set the shared key between the client and the server 
 * (stored into an hidden file named after the client name)
 * @params:
 *          sock: socket to do the search
 *          key: the key to be stored
 */
void Server::setKey(int sock, unsigned char* key) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            
            string filename = "." + p -> Name;
            writeFile((const char*)filename.c_str(), key, keySize);
            
        }
    }
    
}

/**
 * Get the shared key
 * @params: 
 *          sock: the socket of the client in order to do the search
 * @return: 
 *          the filename that contains the key
 */
const char* Server::getKey(int sock) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            
            string filename = "." + p -> Name;
            return (const char*)filename.c_str();
            
        }
    }
    
    return NULL;
    
}

/**
 * get the shared secret between the client and the server
 * @params:
 *          sock: to do the search
 *          size: (OUT) size of the shared secret
 * @return:
 *          the shared secret
 */
unsigned char* Server::getSecret(int sock) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            
            if( p -> secret != NULL) {
                return p -> secret;
            }
            
        }
    }
    
    return NULL;
    
}

/*******************************************************************************
 * PRIVATE FUNCTIONS TO DEAL WITH THE PROTOCOL
 * ****************************************************************************/

/**
 * this function is used in the second step of the protocol and it's useful
 * for key confirmation, the server takes the client's nonce, modifies it
 * and sends it back to the source. The structure of the received message is:
 * |Nc |Ns |Sk |Sc | where:
 * Nc = nonce client (integer)
 * Ns = nonce server (integer)
 * Sk = shared key (16 bytes)
 * Sc = Shared secret (20 bytes)
 * total: 108 bytes
 * @parameters: 
 *              message: the received message
 *              size (OUT): the size of the received message at first then
 *                          the size of the returned buffer
 * @return:
 *              buffer that contains the reply
 * NOTE: free of message done here
 */
unsigned char* Server::settleReply(unsigned char* message, unsigned int* size) {
    
    cliMessage* cm = (cliMessage*) message;
    unsigned int clientNonce = cm -> nonceClient;
    clientNonce --;
    free(message);
    message = (unsigned char*)&clientNonce;
    return message;
    
}

/**
 * Verify if the received message (after eventually desteganograpy) is compliant
 * with the specific of the real protocol and with what it's expected from that
 * client, if the nonce is fresh and so on.
 * @params:
 *          sock: socket on which the message has been received
 *          message: the received message
 *          size: the size of the message
 * @return:
 *          if the message is compliant or not
 */
bool Server::verifyReceivedMsg(int sock, unsigned char* message, int size) {
    
    int len = size;
    int serverNonce;
    unsigned char* key, *secret;
    //first verifiy the integrity of the message
    if( ! k.compareHash((char*)message, &len) ) {
        
        cerr<<"altered message STOP!"<<endl;
        return false;
        
    }

    cliMessage* cm = (cliMessage*) message;
    serverNonce = cm -> nonceServer;
    
    if(serverNonce != nonce) {
        
        cerr<<"Nonce is different, replay attack probably don't listen to this client"
            <<endl;
        return false;
        
    }
    
    //get the key and the secret
    key = cm -> key;
    secret = cm -> secret;
    
    if(memcmp(secret, getSecret(sock), hashLen) != 0) {
        
        cerr<<"wrong secret received"<<endl;
        return false;
        
    }
    setKey(sock, key);
    
    return true;
    
}


/** 
 * Receive a message from a client
 * NOTE: desteganography and decryptography are done here
 * @params
 *          sock: socket of the client to who the server is sending the message
 *          msg: (OUT) the message received
 *          len: (OUT) the length of the received message
 * @returns
 *          how the receive has gone
 */
bool Server::RecvClientMsg(int sock, unsigned char* msg, unsigned int* len) {
    
    unsigned int size = *len;
    unsigned char* decsMsg;
    
    //if the receive has gone wrong then return false
    if( !receiveBuffer(sock, msg, &size) ) {
        return false;
    }
    
    //check if we have to extract the message from the image
    if(steganoMode) {
        
        steno s = steno();
        decsMsg = (unsigned char*)s.readMessage(msg, &size);
        free(msg);
        msg = decsMsg;
        
    }
    
    //check if we have already exchanged a protocol with the key
    if( getEncrypt(sock) == Symmetric ) {
        
        decsMsg = k.secretDecrypt(msg, &size, getKey(sock));
        free(msg);
        msg = decsMsg;
        
    }
    
    //check if we have to do a private key decryption
    if( getEncrypt(sock) == Asymmetric) {
        
        decsMsg = k.asymmetricDecrypt("priv.pem", msg, (unsigned int*)&size);
        free(msg);
        msg = decsMsg;
        
    }
    
    *len = size;
    return true;
}

/** 
 * Send a client a message
 * NOTE: steganography and cryptography are done here
 * NOTE: the client has only the symmetric key, so we can do just the symmetricÃ¹
 * encryption here
 * @params
 *          sock: socket of the client to who the server is sending
 *          msg: the effective message
 *          len: the length of the message
 * @returns
 *          how the send went 
 */
bool Server::SendClientMsg(int sock, unsigned char* msg, unsigned int len) {
    
    unsigned int size = len;
    unsigned char* esMsg;
    
    //if encryption is needed then do it
    if( getEncrypt(sock) ) {
        
        esMsg = k.secretEncrypt(msg, &size, getKey(sock));
        free(msg);
        msg = esMsg;
        
    }
    
        //if the flag is UP then do the steganography
    if(steganoMode == true) {
        
        esMsg = s.LSBSteno(msg, &size);
        //prepare the variables in order to be compliant with the same send
        free(msg);
        msg = esMsg;
        
    }
    
    return sendBuffer(sock, msg, size);
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
    arrivedClient.encrypt = None;
    memset(arrivedClient.secret, 0, 20);
    
    //insert the client in the list (last action to do)
    clientList.push_back(arrivedClient);
    
    cout<<"Arrived client "<<arrivedClient.expMsgLen<<endl;
    
}

/* 
 * Changes the public and the private key of the server
 */
void Server::changeKey(){
    k.asymmetricKeyGenerator();
}

/* 
 * A simple help display on stdout
 */
void Server::displayHelp(){
    
    cout<<"Possible commands are:\n"
        <<"'h' displayHelp\n"
        <<"'k' change public and private key\n"
        <<"'s' use of steganography\n"
        <<"'p' start the protocol\n"
        <<"'q' quit the program\n"<<endl;
    
}


/* 
 * NOTE: possible commands:
 * 'h': help
 * 'k': changeKeys
 */
void Server::parseKeyCommand(){
    
    char cmd;
    char client[maxClientName];
    cin>>cmd;
    bool res = false;
    
    //now we have the command in the cmd variable
    switch(cmd) {
        case 'h':
            displayHelp();
            break;
        case 'k':
            changeKey();
            cout<<"Key changed"<<endl;
            break;
        //steganography session
        case 's':
            steganoMode = true;
            cout<<"Steganography Mode set"<<endl;
            break;
        case 'p':
            cin>>client;
            res = protocol(client);
            cout<<res<<endl;
            //TODO: do something if the protocol goes wrong (e.g enhance security)
            break;
        case 'q':
            exit(1);
            break;
        default:
            break;
    }
    
}

/**
 * Send the requested file if possible otherwise return an error message 
 * @params:
 *          text: is the command + filename
 *          size: (INOUT) at first the size of the message
 *                      then the size of the file plus its hash
 * @return
 *          the message to send to the client
 * NOTE: the allocated virtual memory for msg.text is deleted
 */
unsigned char* Server::prepareFile(char* text, int* len) {
    
    unsigned char* defBuffer;
    
    //cout<<msg.text<<endl;
    int size = 0;
    //read the content of a file
    char* buffer = readFile(text, &size);
    
    //if a buffer is empty then send the client an error message
    if(buffer == NULL) {
        return NULL;
    }
    
    //otherwise compute hash, encrypt the buffer and send it to the client
    else {
        
        //BEGIN HASH COMPUTATION
        int tmpSize = size;
        unsigned char* hashBuf = k.generateHash(buffer, &size);
        size = size + tmpSize; //size of file plus its hash
        defBuffer = new unsigned char[(size)];
        //copy at the beginning the buffer
        memcpy(defBuffer, buffer, tmpSize);
        //now copy the hash computed
        memcpy(&defBuffer[tmpSize], (const char*)hashBuf, (size - tmpSize));
        delete(buffer);
        //END HASH COMPUTATION
		
       *len = size;
    }
    return defBuffer;
    
}

/**  
 * Parse the received message and decide the action to perform
 * NOTE: The message received has already been decrypted and eventually 
 *          desteganographed   
 * @params:
 *          size: dimension of the message
 *          sock: the socket on which we receive the message
 *          text: the received message
 */
/* NOTE: command issued by the client is 6 bytes long for semplicity*/
void Server::parseReceivedMessage(int sock, unsigned char* text, int size) {
    
    //search the client structure in which we have some infos
    clientInfo cl = searchListSocket(sock);
    int len;
    len = size;
    
    /*
     * in the login we receive the client name and the hash of the secret, it's
     * done in the clear for sake of simplicity, in a real-world example this 
     * approach may cause any kind of disaster.
     */ 
    if(cl.protoStep == TODOLOGIN) {
        //if the client has issued a login command than the server fills it 
        if(strncmp("login ", (const char*)text, 6) == 0) {
            
            int startSecret;
            //the client sends its name and the hash of the scret 
            //along with the command so jump after the command
            text += 6; 
            len -= 6;
            //this is when the hash of secret starts
            startSecret = len - hashLen;
            cl.Name = string((char*)text, startSecret);
            
            list<clientInfo>::iterator p = clientList.begin();
            list<clientInfo>::iterator q = clientList.end();
            
            //scan the list and update the right client
            for(; p!=q; p++) {
                if(p->clientSock == cl.clientSock) {
                    p->Name = cl.Name;
                    p->protoStep = DONELOGIN;
                    memcpy(p -> secret, &text[startSecret], hashLen);
                }
            }
            delete(text);
            cout<<"Client Name: "<<cl.Name<<endl;
            SendClientMsg(sock, (unsigned char*)"Login OK\0", strlen("Login OK\0"));
            
        }
        
        //send an error message
        else {
            SendClientMsg(sock, (unsigned char*)"Wrong Request\0", 
                          strlen("Wrong Request\0"));
        }
        
    }
    
    //check if we have received a file request
    if(strncmp("fireq ", (const char*)text, 6) == 0) {
        
        text[len-1] = '\0';
        len -= 6;
        text += 6;
        
        unsigned char* reqFile = prepareFile((char*)text, &len);
        
        if( reqFile == NULL)
            SendClientMsg(sock, (unsigned char*)"Wrong file req\0", 
                          strlen("Wrong file req\0"));
        
        if( !SendClientMsg(sock, reqFile, len) )
            cerr<<"error in answering the request of the client"<<endl;
        else
            cerr<<"send ok"<<endl;
    }
    
    //print the message if it doesn't match any of the operation provided by the server
    else {
        
        cout<<text<<endl;
        
    }
}

/* 
 * Handles the receiving of events from the outside world
 */
void Server::receiveEvents() {
    
    unsigned char* buffer = NULL;
    unsigned int len;
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
                    if( !RecvClientMsg(i, buffer, &len) ) {
                        cerr<<"Error in receiving the message"<<endl;
                        break;
                    }
                    parseReceivedMessage(i, buffer, len);
                }
            break;
            }
        }
    }
}

/** 
 * Protocol to exchange the key with the client
 * @params:
 *          client: the name of the client with who communicate
 * @return:
 *          the exit of the sending
 */
bool Server::protocol(char* client) {
    
    unsigned char* message = NULL, *tmpMessage = NULL;
    unsigned int size;
    
    //search the client in the list
    clientInfo cl = searchListByName(client);
    
    //send to the client a message consisting of the nonce
    if(SendClientMsg(cl.clientSock, (unsigned char*)&nonce, 
        sizeof(int)) == false) {
        
        cerr<<"error in sending the nonce to the client"<<endl;
        return false;
        
    }
    
    //set the required encryption in the reply from the client
    setEncrypt(cl.clientSock, Asymmetric);
    
    //receive the replay from the client, if necessary the message will be deStegoed
    if(RecvClientMsg(cl.clientSock, message, &size) == false) {
        
        cerr<<"error in receiving the message from the client"<<endl;
        return false;
        
    }
    
    /* 
     * now verify that the received message is compliant with the specifics
     * in the verify (if all is compliant) the key generated by the client is 
     * written into a file named after the client
     */
    if(verifyReceivedMsg(cl.clientSock, message, size)) {
        
        tmpMessage = settleReply(message, &size);
        free(message);
        message = tmpMessage;
        
        //from now on all messages will be exchanged through the shared key
        setEncrypt(cl.clientSock, Symmetric);
        
        //send the message encrypted by means of the secret key
        if(SendClientMsg(cl.clientSock, message, size) == false) {
            
            cerr<<"error in sending a message to the client"<<endl;
            return false;
            
        }
        
        return true;
        
    }
    
    else {
        
        cerr<<"Wrong replay from the client"<<endl;
        return false;
        
    }
    
}


/* 
 * Destroyer of the server
 */
Server::~Server(){
    clientList.clear();
}

