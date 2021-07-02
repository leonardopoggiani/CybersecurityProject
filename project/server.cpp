#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "include/server.h"
#include "include/constants.h"

using namespace std;

int main(int argc, char* const argv[]) {

    int* ret;
    unsigned char* buffer;
    serverConnection *server_connection = new serverConnection();

    while(1) {

        cout << "--- waiting for connections ---" << endl;

        server_connection->initSet();
        server_connection->selectActivity();

        if(server_connection->isFDSet(server_connection->getMasterFD())) {
            server_connection->accept_connection();
        } else {    
            for(unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  
                int sd = server_connection->getClient(i);
                if (server_connection->isFDSet(sd)) {

                    buffer = server_connection->receive_message(sd, &ret);
                    if( *ret == -1 ){
                        server_connection->disconnectHost(sd, i);
                    } else {
                        cout << "Message correct" << endl;
                    }
                }  
            }
        }
    }

    return 0;

}

