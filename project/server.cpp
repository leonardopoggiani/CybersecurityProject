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

<<<<<<< HEAD
    int* ret;
    unsigned char* buffer;
    Server srv;
    
=======
    int ret;
    char* buffer = new char[constants::MAX_MESSAGE_SIZE];
    serverConnection *server_connection = new serverConnection();
>>>>>>> main

    while(1) {

        cout << "--- waiting for connections ---" << endl;

        srv.serverConn->initSet();
        srv.serverConn->selectActivity();

        if(srv.serverConn->isFDSet(srv.serverConn->getMasterFD())) {
            srv.serverConn->accept_connection();
        } else {    
            for(unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  
<<<<<<< HEAD
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
=======
                int sd = server_connection->getClient(i);

                if (recv(sd, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0) {
                    server_connection->disconnect_host(sd, i);
                    continue;
                }

                if (server_connection->isFDSet(sd)) {              
                    ret = server_connection->receive_message(sd, buffer);
                    string command(buffer);
                    cout << "Command: " << command << endl;
                    if(command.compare("1") == 0) {
                        cout << "\n**** AUTHENTICATION ****" << endl;
                    } else if(command.compare("2") == 0) {
                        cout << "\n**** ONLINE USERS REQUEST ****" << endl;
                    }else if(command.compare("3") == 0) {
                        cout << "\n**** REQUEST TO TALK****" << endl;
                    }else if(command.compare("4") == 0) {
                        cout << "\n**** CHAT ****" << endl;
                    }else if(command.compare("5") == 0) {
                        cout << "\n**** LOGOUT ****" << endl;
                        server_connection->disconnect_host(sd, i);
                        continue;
                    } else {
                        cout << "Invalid command, please retry" << endl;
                        continue;
>>>>>>> main
                    }
                }  
            }
        }
    }

    if(buffer != NULL)
        delete [] buffer;

    return 0;

}

