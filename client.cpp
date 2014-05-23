#include "client.h"

/** 
 * Client constructor
 * @params:
 *          port: port on which the client is attached to
 *          name: name of the client
 *          server: name of the server
 */
Client::Client(int port, const char* n, const char* server){
    
    //name of the client
    name = string(n);
    
    //socket of the client
    cliSock = socket(AF_INET, SOCK_STREAM, 0);
    
    //ip address of the client
    bzero(&cliAddr, sizeof(cliAddr));
    cliAddr.sin_family=AF_INET;
    cliAddr.sin_port=htons(port);
    struct hostent* he;
    if(inet_aton(server, &cliAddr.sin_addr)!=0) {
        cerr<<"client created\n";
        he=gethostbyname(server);
        if(!he) {
            cerr<<"Can't solve server name"<<server<<" \n";
            exit(1);
        }
        cliAddr.sin_addr =* (struct in_addr*) he->h_addr;
    }
    
    //connect with the socket of the server
    if(connect(cliSock, (struct sockaddr*) &cliAddr, sizeof(cliAddr) )<0) {
        cerr<<"Can't connect socket tcp\n";
        exit(-1);
    }
    
    waitFile = false;
    
    /* 
     * generate a secretKey, the key has to be generated just 
     * once in the whole program
    */
    k = Key();
    s = steno();
    StegoMode = false;
    mode = None;
    
}

/** 
 * Receive a message from the server
 * @params:
 *          msg: (OUT) the received message
 *          len: (OUT) the size of the message
 * @return 
 *         wether the message was received correctly or not
 */
unsigned char* Client::recvServMsg(unsigned int* len) {
    
    unsigned int size = *len;
    unsigned char* decsMsg, *msg;
    
    //if the receive has gone wrong then return false
    if( (msg = receiveBuffer(cliSock, &size)) == NULL) {
        return NULL;
    }
    
    //check if we have to extract the message from the image
    if(StegoMode) {
        
        steno s = steno();
        decsMsg = (unsigned char*)s.readMessage(msg, &size);
        free(msg);
        msg = decsMsg;
        
    }
    
    //check if we have already exchanged a protocol with the key
    if( mode == Symmetric ) {
        
        decsMsg = k.secretDecrypt(msg, &size);
        free(msg);
        msg = decsMsg;
        
    }
    
    *len = size;
    return msg;
    
}

/**
 * Send a message to the server
 * @params
 *          mesg: the text of the message the client sends
 *          len: length of the text
 * @returns
 *          the result of the send
 * NOTE: the size of messages may be sent in the clear since if the adversary 
 * does anything against the communication, then the parties are able to detect 
 * that there's an intruder eavesdropping or manipulating the flow of messages
 */
bool Client::sendServMsg(unsigned char* msg, unsigned int len){
    
    unsigned int size = len;
    unsigned char* esMsg;
    
    //checks if encryption mode is symmetric, then do it before sending
    if( mode == Symmetric ) {
        
        esMsg = k.secretEncrypt(msg, &size);
        free(msg);
        msg = esMsg;
        
    }
    
    //checks if encryption mode is asymmetric, then do it before sending
    if( mode == Asymmetric ) {
        
        esMsg = k.asymmetricEncrypt("server/pub.pem", msg, &size);
        free(msg);
        msg = esMsg;
        
    } 
    
    //if the flag is UP then do the steganography
    if(StegoMode == true) {
        
        esMsg = s.LSBSteno(msg, &size);
        //prepare the variables in order to be compliant with the same send
        free(msg);
        msg = esMsg;
        
    }
    
    return sendBuffer(cliSock, msg, size);
    
}

void Client::displayHelp() {
    cout<<"h -> shows the help!\n"
    <<"s -> insert a message to send to the server\n"
    <<"k -> change the couple of private and public key"
    <<"c -> insert a command"
    <<"f -> request a file"
    <<"l -> the client does a login with its name"<<endl;
    /*
     * FIXME: at first the name and passowrd are sent in the clear, 
     * modify it with the usage of asymmetric encryption.
     */ 
}

/* 
 * Parse the command received from the keyboard
 */
/* 
 * NOTE Possible commands are:
 * h -> help displayHelp
 * s -> new message to be sent to the server
 * k -> change the couple of public and private key
 * c -> insert a command  
 * p -> to start the protocol with the nonce received by the server
 */
/* 
 * NOTE: commands to be given to the server are 5 bytes plus a space,
 * possibilities are: 
 * fireq: requests a file from the server
 * login: does a login to the server
 * encry: encrypt a message
 * mexit: quit from the server
 * steno: required steganography
 */
void Client::parseKeyCommand(char t) {
    
    char text[100];
    char secret[100];
    //command plus the text
    unsigned char* textMsg = NULL, *hs;
    unsigned int len, len1;
    bool messageToSend = false, exitCmd = false;
    
    string message;
    const char* login = "login ";
    const char* fireq = "fireq ";
    const char* quit = "mexit ";
    const char* steganography = "steno ";
    
    //check the command typed by the client
    /* 
     * at the end of the switch we will have the whole message in the variable
     * message and its len in the vairable len
     */
    switch(t) {
        case 'h':
            displayHelp();
            break;
        //this means a new message to send in the clear
        case 'c':
            messageToSend = true;
            cin>>text;
            len = strlen(text);
            textMsg = new unsigned char[len + 1];
            memcpy(textMsg, text, len);
            break;
        //file request
        case 'f':
            messageToSend  = true;
            cin>>text;
            //request a file
            message = fireq + string(text);
            len = message.length();
            textMsg = new unsigned char[len];
            memcpy(textMsg, message.c_str(), len);
            waitFile = true;
            break;
        //login command
        /* 
         * login + clientName + hash of the secret
         */
        case 'l':
            messageToSend = true;
            cout<<"Insert name: ";
            cin>>text;
            len = strlen(text);
            cout<<"Insert the secret: ";
            cin>>secret;
            len1 = strlen(secret);
            hs = k.generateHash((char*)secret, &len1);
            message = login + string(text);
            len = message.length() + len1;
            textMsg = new unsigned char[len];
            memcpy(textMsg, message.c_str(), len - len1 );
            memcpy(&textMsg[len - len1], hs, len1);
            free(hs);
            break;
        //set symmetric encryption mode
        case 'e':
            mode = Symmetric;
            break;
        //set asymmetric encryption mode
        case 'p':
            mode = Asymmetric;
            break;
        //tells to the server and prepare the client to quit
        case 'q':
            messageToSend = true;
            textMsg = new unsigned char[sizeCommand];
            memcpy(textMsg, quit, sizeCommand);
            len = (unsigned int)sizeCommand;
            exitCmd = true;
            break;
        //set the parameters to tell to the server to apply steganography
        case 's':
            messageToSend = true;
            textMsg = new unsigned char[sizeCommand];
            memcpy(textMsg, steganography, sizeCommand);
            len = (unsigned int)sizeCommand;
            break;
        default:
        break;
        
    }
    
    if(!messageToSend)
        return;
    
    if( !sendServMsg(textMsg, len) )
        cerr<<"error in sending the message"<<endl;
    
    //free the virtual allocated memory
    if(textMsg != NULL)
        delete(textMsg);
    
    if(exitCmd == true) 
        exit(1);
    
}

/** 
 * Parse the message received by the server, in this case the waitReplay
 * to see if the client can do an assumption on the received message
 * @params:
 *          msg: the received message
 */
void Client::parseRecMessage(unsigned char* text,unsigned int size) {
    
    unsigned int len;
    unsigned char* buffer;
    
    //first check the message
    if(strcmp ((const char*)text, "wrong file") == 0) {
        cerr<<"wrong file requested"<<endl;
        return;
    }
    
    //wait for a file and decrypts it
    if(waitFile == true) {
        Key k = Key(); 
        len = size;
        buffer = k.secretDecrypt((const unsigned char*)text, &len);
        //printByte(buffer, size);
        
        //cout<<"********************\n\n\n**************\n\n"<<endl;
        
        bool notAltered = k.compareHash((char*)buffer, &len);
        //this means the hash aren't equal
        if(!notAltered) {
            cerr<<"intruder modified something"<<endl;
            exit(-1);
        }
        cout<<buffer<<endl;
        cout<<" *** "<<text<<" *** "<<endl;
        writeFile("out.pdf", buffer, size);
        delete(buffer);

    }
    
    if(strncmp((const char*)text, "Nonce ", sizeCommand) == 0) {
        
        protocol(text, size);
        
    }
    
    delete(text);
    
}

/* 
 * Receive events from the outside world, server socket or keyboard
 */
void Client::receiveEvents() {
    
    
    unsigned char* buffer = NULL;
    unsigned int len;
    //cerr<<"receive events\n";
    fdmax = cliSock;
    //infinite loop to accept events
    while(1) {
        
        FD_SET(0, &read_fds);
        FD_SET(cliSock, &read_fds);
        
        int sel = select(fdmax+1, &read_fds, NULL, NULL, NULL);
        if( sel <= 0) {
            cerr<<" error in the select "<<name<<" \n";
            exit(1);
        }
        
        //cerr<<"receive events"<<endl;
        
        //this means keyboard event
        if(FD_ISSET(0, &read_fds)) {
            //cout<<"key pressed"<<endl;
            char k;
            cin>>k;
            parseKeyCommand(k);
        }
        
        /* 
         * roll all the file descriptors and
         * checks if the file descriptor has been set
         */ 
        for(int i=1; i<=fdmax; i++) {
            
            //cerr<<"for cycle "<<i<<endl;
            
            if(FD_ISSET(i, &read_fds)) {
                
                //receive the message from the server and parse it
                if(i == cliSock) {
                    
                    if( (buffer = recvServMsg(&len)) == NULL ) {
                        
                        cerr<<"error in receiving the message"<<endl;
                        break;
                        
                    }
                    parseRecMessage(buffer, len);
                    
                }
                
            }
        }
    }
}

/**
 * This is the function to establish the key between the client and the server
 * The message received from the server hash the following structure:
 *  "Nonce " numberNonce
 * @params:
 *          msg: the message received from the server
 *          size: the size of the message
 */
void Client::protocol(unsigned char* msg, unsigned int size) {
    
    nonceType servNonce;
    memcpy(&servNonce, &msg[sizeCommand], sizeof(nonceType));
    unsigned int totMsgSize;
    unsigned char* totMsg, *tmpMsg1;
    unsigned int len;
    
    //the client prepares the reply
    cliMessage* cm = new cliMessage;
    cm -> nonceServer = servNonce;
    
    cNonce = cm -> nonceClient = generateNonce();
    //generate the key and then read it
    k.secretKeyGenerator();
    //FIXME: to optimize modifying something
    unsigned char* tmpKey = readKeyFile("key.txt", (int)keySize); 
    memcpy( cm -> key, tmpKey, keySize);
    free(tmpKey);
    
    //ask the client to insert the secret
    cout<<"Insert secret"<<endl;
    unsigned char secret[200];
    cin>>secret;
    
    len = strlen((const char*)secret);
    
    //hash the secret because 
    
    memcpy(cm -> secret, k.generateHash((char*)secret, &len), hashLen);
    //cm -> padding = generatePadding(&len);
    //set the mode to asymmetric
    mode = Asymmetric;
    
    /*
    //do te preparation of the message
    cliMessageLength = 2 * sizeof(nonceType) + len + hashLen + keySize; 
    unsigned char* hashMsg = k.generateHash((unsigned char*)cm, &len);
    totMsgSize = cliMessageLength + len;
    totMsg = new unsigned char[totMsgSize];
    memcpy(totMsg, (void*)cm, cliMessageLength);
    memcpy(&totMsg[cliMessageLength], hashMsg, len);
    */
    
    unsigned int tmpLength = 2* sizeof(nonceType) + len + keySize + hashLen;
    unsigned  char* tmpMsg = new unsigned char[tmpLength];
    memcpy(tmpMsg, (void*)cm, tmpLength);
    //tmpMsg[tmpLength] = '\0';
    
    unsigned int tmp = tmpLength;
    
    totMsgSize = tmpLength + hashLen;
    totMsg = new unsigned char[totMsgSize];
    memcpy(totMsg, tmpMsg, tmp);
    unsigned char* hashMsg = k.generateHash((char*)tmpMsg, &tmp); 
    memcpy(&totMsg[tmpLength], hashMsg, hashLen);
    bool result = k.compareHash((char*)totMsg, &totMsgSize);
    cout<<result<<endl;
    
    totMsgSize = tmpLength + hashLen;
    //before the sending do all the needed free
    //free(cm -> padding);
    free(cm);
    //free(tmpKey);
    free(hashMsg);
    
    //cout<<"Printing before the send:"<<endl;
    //printByte(totMsg, totMsgSize);
    //cout<<endl<<"**************************"<<endl;
    if( !sendServMsg(totMsg, totMsgSize) ) {
        
        cerr<<"wrong message sent"<<endl;
        free(totMsg);
        return;
        
    }
    cerr<<"message sent"<<endl;
    //free(totMsg);
    
    mode = Symmetric;
    
    /* after the send of the message the client expects its nonce modified
     * encrypted by means of the symmetric key
     */
    if( (tmpMsg1 = recvServMsg(&totMsgSize) ) == NULL ) {
        
        cerr<<"wrong message received"<<endl;
        free(totMsg);
        return;
        
    }
    cerr<<"message received: "<<totMsgSize<<endl;
    
    printByte(tmpMsg1, totMsgSize);
    
    if( !k.compareHash((char*)tmpMsg1, &totMsgSize) ) {
        
        cerr<<"Alert! message altered"<<endl;
        free(totMsg);
        return;
        
    }
    
    nonceType recNonce;
    memcpy((void*)& recNonce, tmpMsg1, totMsgSize);
    
    //check if the nonce was received correctly
    if( recNonce == (cNonce - 1) ) {
        
        mode = Symmetric;
        return;
        
    }
    
    else {
        
        mode = None;
        cerr<<"Wrong protocol execution"<<endl;
        return;
        
    }
    
    
}


Client::~Client(){

}