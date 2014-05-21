#include "server.h"
#include "steganography.h"
//main server
int main(int argc, char **argv) {
    cout << "Hello, world!" << std::endl;
    int size;
    char* tmp = readFile("file.png", &size);
    //cin >> tmp;
    int len = size;
    Server s = Server("localhost", 1238);
    s.receiveEvents();
    
    //steno s1 = steno();
    //cout<<size<<endl;
    //s1.LSBSteno(tmp, &size);
    //cout<<len<<endl;
    //s1.readMessage("hello.bmp", &len);
    
    return 0;
}
