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
    fdmax=servSock;
    
    steganoMode = false;

    //initialize the string
    name = string(host);
    
    clientList = list<clientInfo>();
    
    nonce = generateNonce();
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

/**
 * search the max socket in the list
 * @return:
 *          the highest socket number
 */
int Server::maxSock() {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    int maxSock = 0;
    
    for(; p != q; p++) {

        if(p -> clientSock > maxSock)
            maxSock = p->clientSock;
    }
    
    return maxSock;
    
}

/**
 * Set the eventually steganography mode for that client
 * @params:
 *          name: the name of the client
 *          sMode: the mkode to set
 */
void Server::setStegoMode(char* name, bool sMode) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    clientInfo t;
    
    for(; p != q; p++) {

        if( strcmp(p -> Name.c_str(), name) == 0) {
            
            p -> sMode = sMode;
            
        }
    }
}

/**
 * Check if the client has the steganography mode set
 * @params:
 *          sock: parameter to do the search
 * @return:
 *          the stegoMode
 */
bool Server::getStegoMode(int sock) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    clientInfo t;
    
    for(; p != q; p++) {

        if( p -> clientSock == sock ) {
            
            return p -> sMode;
            
        }
    }
    
    return false;
    
}


/** 
 * Remove a client from the list and then eventually re-arrange the file 
 * descriptors in order to not have any errors
 * @params:
 *          sock: socket of the client to be deleted
 */
void Server::removeClient(int sock) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    int remSock;
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            
            remSock = sock;
            clientList.erase(p++);
            
            //now rearrange file descriptors
            if(fdmax == remSock) 
                fdmax = maxSock();
        }
    }
    
    printList();
    
}

/**
 * Search the socket in the list
 * @params:
 *          sock: the number of the socket
 * @return
 *          the outcome of the find
 */
bool Server::presentSock(int sock) {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    
    for(; p != q; p++) {

        if(p -> clientSock == sock) {
            //cout<< p -> Name << " socket present" <<endl;
            return true;
            
        }
    }
    
    return false;
    
}

//prints the clients in the list
void Server::printList() {
    
    list<clientInfo>::iterator p = clientList.begin();
    list<clientInfo>::iterator q = clientList.end();
    
    for(; p != q; p++) 
        
        cout<<p -> Name << '\t';
    
    cout<<endl;
        
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
 * Hash of all: 20 bytes
 * total: 84 bytes
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
    nonceType clientNonce = cm -> nonceClient;
    clientNonce --;
    delete(message);
    unsigned char* tmp = new unsigned char[sizeof(nonceType)];
    memcpy(tmp, (void*)&clientNonce, sizeof(nonceType));
    //message = (unsigned char*)&clientNonce;
    *size = sizeof(nonceType);
    return tmp;
    
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
bool Server::verifyReceivedMsg(int sock, unsigned char* message, 
                               unsigned int size) {
    
    unsigned int len = size;
    nonceType serverNonce;
    unsigned char* key, *secret;
    //first verifiy the integrity of the message
    if( ! k.compareHash((char*) message, &len) ) {
        
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

/******************************************************************************/

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
unsigned char* Server::RecvClientMsg(int sock, unsigned int* len) {
    
    unsigned int size, tmpSize;
    unsigned char* decsMsg, *msg;
    
    /* 
     * At first receive the size of the expected message with its hash and then 
     * compare the received hash with the expected one
     */
    size = sizeof(unsigned int) + hashLen;
    
    unsigned char* sBuf = receiveBuffer(sock, &size);
    if( sBuf == NULL ) {
        return NULL;
    }
    
    if( k.compareHash((char*)sBuf, &size) == false ) {
        cerr<<"mesage altered "<<sBuf<<endl;
        return NULL;
    }
    
    memcpy( (void*)&tmpSize, (void*)sBuf, sizeof(unsigned int) );
    //cerr<<"receive size of the message "<<tmpSize<<endl;
    size = tmpSize;
    
    //if the receive has gone wrong then return false
    if( (msg = receiveBuffer(sock, &size)) == NULL ) {
        return NULL;
    }
    
    //cout<<msg<<endl;
    
    //check if we have to extract the message from the image
    if( getStegoMode(sock) ) {
        
        steno s = steno();
        decsMsg = (unsigned char*)s.readMessage(msg, &size);
        delete(msg);
        msg = decsMsg;
        
    }
    
    //check if we have already exchanged a protocol with the key
    if( getEncrypt(sock) == Symmetric ) {
        
        decsMsg = k.secretDecrypt(msg, &size, getKey(sock));
        delete(msg);
        msg = decsMsg;
        
    }
    
    //check if we have to do a private key decryption
    if( getEncrypt(sock) == Asymmetric) {
        
        decsMsg = k.asymmetricDecrypt("priv.pem", msg, (unsigned int*)&size);
        delete(msg);
        msg = decsMsg;
        
    }
    
    *len = size;
    return msg;
}

/** 
 * Send a client a message
 * NOTE: steganography and cryptography are done here
 * NOTE: the client has only the symmetric key, so we can do just the symmetric
 * encryption here
 * @params
 *          sock: socket of the client to who the server is sending
 *          msg: the effective message
 *          len: the length of the message
 * @returns
 *          how the send went 
 */
bool Server::SendClientMsg(int sock, unsigned char* msg, unsigned int len,
                           int flag) {
    
    unsigned int size = len;
    unsigned char* esMsg;
    unsigned int hSize = sizeof(unsigned int) + hashLen;
    
    //compute the hash of the message
    
    //if encryption is needed then do it
    if( getEncrypt(sock) ) {
        
        esMsg = k.secretEncrypt(msg, &size, getKey(sock));
        delete(msg);
        msg = esMsg;
        
    }
    
        //if the flag is UP then do the steganography
    if( getStegoMode(sock) )  {
        
        esMsg = s.LSBSteno(msg, &size);
        //prepare the variables in order to be compliant with the same send
        delete(msg);
        msg = esMsg;
        
    }
    
    /*
     * first compute the hash of the size of the message and concatenate it with
     * the size of the message, this is not the safer procedure of course, I 
     * assumed that in the case of the size of the message, the hash corresponds
     * to a digital signature 
    */
    //cerr<<"send size of the message "<<size<<endl;
    unsigned int tmp = sizeof(unsigned int); 
    unsigned char buf[sizeof(unsigned int) + hashLen];
    memcpy(buf, (void*)&size, sizeof(unsigned int));
    unsigned char* hashSize = k.generateHash((char*)&size, 
                                             &tmp);
    memcpy(&buf[sizeof(unsigned int)], hashSize, hashLen);
    delete(hashSize);
    
    //now I can send the size of the message
    sendBuffer(sock, buf, hSize);
    
    bool result = sendBuffer(sock, msg, size);
    if(flag == 1)
        delete(msg);
    return result;
}

/** 
 * Accept a new connection by a client and add it in the list if it's not
 * already present in the list
 */
void Server::acceptConnection() {
    
    clientInfo arrivedClient;
    int len;
    
    //allocate the socket for a new client
    arrivedClient.clientSock = accept(servSock, (sockaddr*) 
        &arrivedClient.clientAddr, (socklen_t*)&len);
    
    if(arrivedClient.clientSock > maxSock())
        fdmax = arrivedClient.clientSock;
    
    FD_SET(arrivedClient.clientSock, &read_fds);
    arrivedClient.Name = string("\0");
    //this means that the login has to be done
    arrivedClient.protoStep = TODOLOGIN;
    arrivedClient.encrypt = None;
    arrivedClient.sMode = false;
    memset(arrivedClient.secret, 0, 20);
    
    //insert the client in the list (last action to do)
    clientList.push_back(arrivedClient);
    
    cout<<"Arrived client "<<endl;
    
}

/** 
 * Changes the public and the private key of the server
 */
void Server::changeKey(){
    k.asymmetricKeyGenerator();
}

/** 
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


/** 
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
            cout<<"Insert client name"<<endl;
            cin>>client;
            setStegoMode(client, true);
            //steganoMode = true;
            cout<<"Steganography Mode set"<<endl;
            //TODO provide a send to all client to inform them of the steno mode
            break;
        case 'p':
            cout<<"Insert client name"<<endl;
            cin>>client;
            res = protocol(client);
            //cout<<res<<endl;
            //TODO: do something if the protocol goes wrong (e.g enhance security)
            if(res) {
                cout<<"Protocol executed in a right way!"<<endl;
                return;
            }
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
unsigned char* Server::prepareFile(char* text,unsigned int* len) {
    
    unsigned char* defBuffer = NULL;
    
    //cout<<msg.text<<endl;
    unsigned int size = 0;
    //read the content of a file
    unsigned char* buffer = (unsigned char*)readFile(text, &size);
    
    //if a buffer is empty then send the client an error message
    if(buffer == NULL) {
        cout<<"NULL buffer"<<endl;
        return NULL;
    }
    
    //otherwise compute hash, encrypt the buffer and send it to the client
    else {
        
        //BEGIN HASH COMPUTATION
        int tmpSize = size;
        unsigned char* hashBuf = k.generateHash((char*)buffer, &size);
        size = size + tmpSize; //size of file plus its hash
        defBuffer = new unsigned char[(size)];
        //copy at the beginning the buffer
        memcpy(defBuffer, buffer, tmpSize);
        //now copy the hash computed
        memcpy(&defBuffer[tmpSize], (const char*)hashBuf, (size - tmpSize));
        delete(buffer);
        delete(hashBuf);
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
    
    const char* login = "Login OK";
    const char* wreq = "Wrong request\0";
    char* respMessage;
    unsigned char* hashComp;
    bool reply = false;
    
    //search the client structure in which we have some infos
    clientInfo cl = searchListSocket(sock);
    bool actionPerformed = false;
    unsigned int len = (unsigned int)size;
    unsigned int len1;
    
    //do a comparison of the hashes in order to check if the message was modified
    if( !k.compareHash((char*)text, &len) ) {
        cout<<"message altered!"<<endl;
        return;
    }
    
    /*
     * in the login we receive the client name and the hash of the secret, it's
     * done in the clear for sake of simplicity, in a real-world example this 
     * approach may cause any kind of disaster.
     */ 
    if(cl.protoStep == TODOLOGIN) {
        //if the client has issued a login command than the server fills it 
        if(strncmp("login ", (const char*)text, 6) == 0) {
            
            int startSecret;
            actionPerformed = true;
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
            delete(text - 6);
            cout<<"Client Name: "<<cl.Name<<endl;
            len1 = strlen(login);
            len = len1;
            respMessage = new char[ len + hashLen ];
            memcpy( respMessage, login, len );
            hashComp = (unsigned char*)k.generateHash( (char*)login, &len1 );
            memcpy( &respMessage[len], 
                    hashComp, (unsigned int) hashLen );
            reply = true;
            len = strlen(login) + hashLen;
            
        }
        
        //send an error message
        else {
            
            actionPerformed = true;
            len = strlen(wreq);
            respMessage = new char[ len + hashLen ];
            hashComp = k.generateHash( (char*)wreq, &len );
            memcpy( respMessage, wreq, strlen(wreq) );
            memcpy( (void*)&respMessage[len], hashComp, (unsigned int) hashLen );
            reply = true;
            len = strlen(wreq) + hashLen;
            
        }
        
    }
    
    //check if we have received a file request
    if(strncmp("fireq ", (const char*)text, 6) == 0) {
        
        actionPerformed = true; 
        len -= 6;
        text += 6;
        
        unsigned char* reqFile = prepareFile((char*)text, &len);
        
        if( reqFile == NULL) {
            
            len = strlen(wreq);
            respMessage = new char[ len + hashLen ];
            hashComp = k.generateHash( (char*)wreq, &len );
            memcpy( respMessage, wreq, strlen(wreq) );
            memcpy( (void*)&respMessage[strlen(wreq)], 
                    hashComp, (unsigned int) hashLen );
            len = strlen(wreq) + hashLen;
            reply = true;
            
        }
        
        else{
            if( !SendClientMsg(sock, reqFile, len) )
                cerr<<"error in answering the request of the client"<<endl;
            else
                cerr<<"send ok"<<endl;
        }
    }
    
    if(strncmp("mexit ", (const char*)text, 6) == 0) {
        
        actionPerformed = true;
        removeClient(sock);
        
    }
    
    //print the message if it doesn't match any of the operation provided by the server
    if(actionPerformed == false) {
        text[len] = '\0';
        cout<<searchListSocket(sock).Name<<": "<<(char*)text<<endl;
        
    }
    
    if( reply ) {
        //cout<<"reply "<<respMessage<<endl;
        if( !SendClientMsg(sock, (unsigned char*)respMessage, len) ){
            cerr<<"error in sending the reply";
            delete(respMessage);
            delete(hashComp);
        }
        //cout<<"resp MSG: "<<(char*)respMessage<<" "<<len<<endl;
        delete(respMessage);
        delete(hashComp);
    }
    
}

/** 
 * Handles the receiving of events from the outside world
 */
void Server::receiveEvents() {
    
    unsigned char* buffer = NULL;
    unsigned int len;
    //file descriptor from which start, we have to skip 
    int fdStart = 3;
    //infinite loop to accept events
    while(1) {
        
        FD_SET(0, &read_fds);
        FD_SET(servSock, &read_fds);
        
        //cout<<"waiting for typing or other event"<<endl;
        
        if(select(fdmax + 1, &read_fds, NULL, NULL, NULL)==-1) {
            cerr<<" error in the select"<<name<<" \n";
            exit(1);
        }
        //cout<<"out of the select!"<<endl;
        
        /* 
         * roll all the file descriptors and
         * checks if the file descriptor has been set
         */
        //this means keyboard event
        if(FD_ISSET(0, &read_fds)) {
            
            //cout<<"input from keyboard"<<endl;
            parseKeyCommand();
            
        }
        //skip the stdin, stdout and stderr
        for(int i = fdStart; i <= fdmax; i++) {
            
            //this means other kind of input
            if( (presentSock(i) || i == servSock) && FD_ISSET(i, &read_fds)) {
                
                //checks if there's a new connections
                if(i == servSock) {
                    //cout<<"new connection"<<endl;
                    acceptConnection();
                    break;
                }
                
                //this means a receiving message
                //NOTE: i > 2 to avoid the stderr and the stdout 
                if(i > 2 && i != servSock) {
                    //cout<<"message received"<<endl;
                    if( (buffer = RecvClientMsg(i,&len)) == NULL  ) {
                        cerr<<"Error in receiving the message"<<endl;
                        break;
                    }
                    parseReceivedMessage(i, buffer, len);
                    //i = fdmax + 1;
                    //break;
                }
                //i = fdmax + 1;
                break;
            }
        }
        //reset the file descriptors
        for( int i = fdStart; i <= fdmax; i++ ) {
            
            if(presentSock(i))
                FD_SET(i, &read_fds);
            
        }
        //cout<<"out of for"<<endl;
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
    unsigned char* tmpHash;
    unsigned int size, tmpSize;
    bool res;
    //search the client in the list
    clientInfo cl = searchListByName(client);
    
    unsigned int sizeFirstMsg = tmpSize = sizeof(nonceType) + sizeCommand;
    unsigned char* firstMsg = new unsigned char[sizeFirstMsg + hashLen];
    memcpy(firstMsg, "Nonce ", sizeCommand);
    memcpy(&firstMsg[sizeCommand], (void*)&nonce,sizeof(nonceType));
    tmpHash = k.generateHash((char*)firstMsg, &tmpSize);
    memcpy(&firstMsg[sizeFirstMsg], tmpHash, hashLen );
    delete(tmpHash);
    sizeFirstMsg = sizeFirstMsg + hashLen;
    
    //send to the client a message consisting of the nonce
    if(SendClientMsg(cl.clientSock, firstMsg, sizeFirstMsg) == false) {
        
        cerr<<"error in sending the nonce to the client"<<endl;
        return false;
        
    }
    
    //set the asymmetric encryption in the reply from the client
    setEncrypt(cl.clientSock, Asymmetric);
    
    //receive the replay from the client, if necessary the message will be deStegoed
    if((message = RecvClientMsg(cl.clientSock, &size)) == NULL) {
        
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
        message = k.generateHash((char*)tmpMessage, &size);
        
        //now I have to concatenate the nonce along with its hash
        unsigned char* totMsg = new unsigned char[sizeof(nonceType) + size];
        memcpy(totMsg, tmpMessage, sizeof(nonceType));
        memcpy(&totMsg[sizeof(nonceType)], message, size);
        
        //printByte(totMsg, sizeof(nonceType) + size);
        
        //from now on all messages will be exchanged through the shared key
        setEncrypt(cl.clientSock, Symmetric);
        
        //send the message encrypted by means of the secret key
        if(SendClientMsg(cl.clientSock, totMsg, sizeof(nonceType) + size) == false) {
            
            cerr<<"error in sending a message to the client"<<endl;
            res = false;
            
        }
        
        res = true;
        
    }
    
    else {
        
        cerr<<"Wrong replay from the client"<<endl;
        res = false;
        
    }
    
    //FD_SET(cl.clientSock, &read_fds);
    nonce = generateNonce();
    return res;
    
}


/** 
 * Destroyer of the server
 */
Server::~Server(){
    clientList.clear();
}

