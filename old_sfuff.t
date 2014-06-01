/** 
 * Receive a message on the socket sock and returns it
 * @params: 
 *          sock the socket on which receive the message
 * @returns: 
 *          the received message
 * 
 * NOTE: depending on the type of text it's up to the caller to
 * insert the EOS (end of string) if needed, in this way this
 * function is more general 
 */
message receiveMessage(int sock, sockaddr* addr) {
    
    message msg;
    unsigned int msg_size;
    socklen_t sizeSockAddr = sizeof(sockaddr);
    
    //receive the message size first
    msg_size = recvfrom(sock, (void*)&msg.len, sizeof(int), MSG_WAITALL, 
                        addr, &sizeSockAddr);
    
    /* compares the received size with the expencted one
     * if the sizes don't match return an empty message */
    if(msg_size < sizeof(int)) {
        cerr<<"error in receiving the size"<<msg.len<<'\n';
        msg.len = 0;
        msg.text = new char[1];
        msg.text[0] = '\0';
        return msg;
    }
    
    //prepare the buffer and receive the message
    msg.text = new char[msg.len];
    msg_size = recvfrom(sock, (void*)msg.text, msg.len, MSG_WAITALL, addr, 
                        &sizeSockAddr);
    /* compares the received size with the expencted one
     * if the sizes don't match return an empty message */
    
    if(msg_size < msg.len) {
        cerr<<"error in receiveing the size\n";
        msg.len = 0;
        free(msg.text);
        msg.text = new char[1];
        msg.text[0] = '\0';
        return msg;
    }
    
    //printByte((unsigned char*)msg.text, msg.len);
    //cout<<"received message "<<msg.text<<endl;
    
    return msg;
}

/* 
 * Send a message on the socket sock and returns it
 * @params:
 *          sock: the socket on which receive the message
 *          msg: the message
 * @returns:
 *          the effectiveness of the operation
 */
bool sendMessage(int sock, message msg, sockaddr* addr) {
    
    //send the size of the message
    unsigned int size = sendto(sock, (void*)&msg.len, sizeof(int), 0,
        addr, sizeof(sockaddr));
    
    if(size < sizeof(int)) {
        cerr<<"error in the len send "<<size<<endl;
        return false;
    }
    
    //send the effective message
    size = sendto(sock, (void*)msg.text, msg.len, 0, 
        addr, sizeof(sockaddr));
    
    if(size < msg.len) {
        cerr<<"error in the text send "<<msg.len<<" "<<size<<endl;
        cerr<<msg.text<<endl;
        return false;
    }
    
    //printByte((unsigned char*)msg.text, msg.len);
    //cout<<"message sent\n";
    return true;
    
}


//from client.cpp
{
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
}

