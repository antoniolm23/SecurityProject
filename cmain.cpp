#include "client.h"

//main client
int main(int argc, char **argv) {
    cout << "Hello, world!" << std::endl;
    
    Client c = Client(1236, "anto", "localhost");
    c.receiveEvents();
    
    return 0;
}
