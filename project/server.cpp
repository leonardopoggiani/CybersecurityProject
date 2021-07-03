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
    Server srv;
    

    while(1) {

        cout << "--- waiting for connections ---" << endl;

        srv.serverConn->initSet();
        srv.serverConn->selectActivity();

        if(srv.serverConn->isFDSet(srv.serverConn->getMasterFD())) {
            srv.serverConn->accept_connection();
        } else {    
            for(unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  
                int sd = srv.serverConn->getClient(i);
                if (srv.serverConn->isFDSet(sd)) {

                    buffer = srv.serverConn->receive_message(sd, &ret);
                    if( *ret == -1 ){
                        srv.serverConn->disconnectHost(sd, i); 
                    } else {
                        
                        cout << "\n-------Authentication-------" << endl;
        
                        if (!authentication(srv, sd)) throw runtime_error("Authentication Failed");
                        cout << "-----------------------------" << endl << endl;

                        cout << "Message correct" << endl;
                    }
                }  
            }
        }
    }

    return 0;

}

