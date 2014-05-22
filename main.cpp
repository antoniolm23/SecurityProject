#include "server.h"

//main server
int main(int argc, char **argv) {
    cout << "Hello, world!" << std::endl;
    
    Server s = Server("localhost", 1235);
    s.receiveEvents();
    
    //steno s1 = steno();
    //cout<<size<<endl;
    //s1.LSBSteno(tmp, &size);
    //cout<<len<<endl;
    //s1.readMessage("hello.bmp", &len);
    
    return 0;
}
