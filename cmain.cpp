#include "client.h"

//main client
int main(int argc, char **argv) {
    cout << "Client starting" << std::endl;
    
    Client c = Client(1234, argv[1], "localhost");
    c.receiveEvents();
    
    return 0;
}
