#include "client.h"
#include "key.h"
/* 
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
    Key k = Key();
    k.secretKeyGenerator();
    mode = None;
    
}

/* 
 * Receive a message from the server
 * @return 
 *         the message received
 */
message Client::recvServMsg(int sock) {
    
    return receiveMessage(sock, &servAddr);
    
}

/* 
 * Send a message to the server
 * @params
 *          msg: the message the client sends
 * @returns
 *          how the sent went
 */
bool Client::sendServMsg(message msg){
    
    return sendMessage(cliSock, msg, &servAddr);
    
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
 */
void Client::parseKeyCommand(char k) {
    
    char text[100];
    //command plus the text
    unsigned char* cmdText;
    int len;
    bool messageToSend = false;
    
    const char* login = "login ";
    const char* fireq = "fireq ";
    const char* enc = "encry ";
    const char* command; 
    
    //check the command typed by the client
    switch(k) {
        case 'h':
            displayHelp();
            break;
        //this means a new message to send in the clear
        case 's':
            cin>>text;
            len = strlen(text);
            break;
        //
        case 'f':
            messageToSend  = true;
            cin>>text;
            len = strlen(text);
            //request a file
            command = fireq;
            fileName = string(text);
            waitFile = true;
            break;
        case 'l':
            messageToSend = true;
            cin>>text;
            len = strlen(text);
            command = login;
            break;
        case 'e':
            encryptionMode = Symmetric;
            break;
        case 'p':
            encryptionMode = Asymmetric;
            break;
        case 'q':
            exit(1);
        default:
        break;
        
    }
    
    if(!messageToSend)
        return;
    
    /*
     * prepare the message to send putting at the beginning the command 
     * and at the end the message put by the client
     */
    len += 6;
    cmdText = new unsigned char[len];
    for(int i = 0; i<6; i++)
        cmdText[i] = command[i];
    memcpy(&cmdText[6], text, (len - 6));
    unsigned char* tmp = new unsigned char[len]; 
    memcpy(tmp, cmdText, len);
    delete(cmdText);
    cout<<tmp<<endl;
    tmp[len] = '\0';
    
    //check if we have to encrypt the message and do it if requested
    if(encryptionMode == Symmetric) {

        Key k = Key();
        cmdText = k.secretEncrypt(tmp, &len);
        //cout<<"successfully encrypted"<<cmdText<<endl;
        //printByte((uint8_t*)cmdText, len);
        delete(tmp);
        //Key k1 = Key();
        //tmp = k1.secretDecrypt(cmdText, &len);
        //cout<<"decrypted: "<<tmp<<endl;
        
        //cout<<"cmdText: "<<cmdText<<endl;
        message* msg = new message;
        msg->len = len + 1;
        msg->text = new char[len + 1];
        memcpy(msg->text, cmdText, len);
        msg->text[len] = '\0';
        //cout<<"second print ";
        //cout<<msg->text<<endl;
        sendServMsg(*msg);
        delete(msg->text);
        delete(msg);
    }
    
    if(encryptionMode == Asymmetric) {
        
        Key k = Key();
        //each key is stored in a folder named after the entity related to
        cmdText = k.asymmetricEncrypt("server/pub.pem", tmp, &len);
        delete(tmp);
        if(cmdText == NULL || len <= 0) {
            cerr<<"Wrong encryption by means of the public key"<<endl;
            return;
        }
        //send the buffer encrypted by means of the server public key
        sendBuffer(cliSock, (unsigned char*)cmdText, len);
        
    }
    
    //free the virtual allocated memory
    delete(cmdText);
    
}

/* 
 * Parse the message received by the server, in this case the waitReplay
 * to see if the client can do an assumption on the received message
 * @params:
 *          msg: the received message
 */
void Client::parseRecMessage(message msg) {
    
    int size;
    unsigned char* buffer;
    
    //first check the message
    if(strcmp (msg.text, "wrong file") == 0) {
        cerr<<"wrong file requested"<<endl;
        return;
    }
    
    //wait for a file and decrypts it
    if(waitFile == true) {
        Key k = Key(); 
        size = msg.len;
        buffer = k.secretDecrypt((const unsigned char*)msg.text, &size);
        //printByte(buffer, size);
        
        //cout<<"********************\n\n\n**************\n\n"<<endl;
        
        bool notAltered = k.compareHash((char*)buffer, &size);
        //this means the hash aren't equal
        if(!notAltered) {
            cerr<<"intruder modified something"<<endl;
            exit(-1);
        }
        cout<<buffer<<endl;
        cout<<" *** "<<msg.text<<" *** "<<endl;
        writeFile("out.pdf", buffer, size);
        delete(buffer);
        delete(msg.text);
    }
    
}

/* 
 * Receive events from the outside world, server socket or keyboard
 */
void Client::receiveEvents() {
    
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
                    
                    message msg = recvServMsg(i);
                    parseRecMessage(msg);
                    
                }
                
            }
        }
    }
}

Client::~Client(){

}