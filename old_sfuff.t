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

