#include "server.h"

//main server
int main(int argc, char **argv) {
    cout << "Server starting" << std::endl;
    Server s = Server("localhost", 1234);
    s.receiveEvents();
    
    //steno s1 = steno();
    //cout<<size<<endl;
    //s1.LSBSteno(tmp, &size);
    //cout<<len<<endl;
    //s1.readMessage("hello.bmp", &len);
    
    return 0;
}
