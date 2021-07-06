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
#include <dirent.h>
#include <regex>
#include "include/server.h"
#include "include/constants.h"

using namespace std;

int main(int argc, char* const argv[]) {

    int ret;
    unsigned char* buffer = new unsigned char[constants::MAX_MESSAGE_SIZE];
    vector<unsigned char> buffToSend;
    vector<unsigned char> vectorBuffer;
    array<unsigned char,constants::MAX_MESSAGE_SIZE> certificate_to_send;
    
    
    int buffToSendLen;
    Server srv;
    X509 *cert;
  
    while(1) {

        cout << "--- waiting for connections ---" << endl;

        srv.serverConn->initSet();
        srv.serverConn->selectActivity();

        if(srv.serverConn->isFDSet(srv.serverConn->getMasterFD())) {
            srv.serverConn->accept_connection();
        } else {    
            for(unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  
                int sd = srv.serverConn->getClient(i);

                if (recv(sd, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0) {
                    srv.serverConn->disconnect_host(sd, i);
                    continue;
                }

                if (srv.serverConn->isFDSet(sd)) {              
                    ret = srv.serverConn->receive_message(sd, buffer);

                    if(ret == 0) {
                        cout << "removing user 1" << endl;
                        srv.serverConn->removeUser(sd);
                        srv.serverConn->printOnlineUsers();
                        srv.serverConn->disconnect_host(sd, i);                      
                        continue;
                    }

                    if(buffer[0] == '1') {
                        cout << "\n**** AUTHENTICATION ****" << endl;
                      
                        if (!authentication(srv, sd, buffer)) throw runtime_error("Authentication Failed On Server");
                        cout << "-----------------------------" << endl << endl;

                    }  /*else if(command.compare("2") == 0) {
                        cout << "\n**** ONLINE USERS REQUEST ****" << endl;
                    }else if(command.compare("3") == 0) {
                        cout << "\n**** REQUEST TO TALK****" << endl;
                    }else if(command.compare("4") == 0) {
                        cout << "\n**** CHAT ****" << endl;
                    } */ else if(buffer[1] == '5') {
                        cout << "\n**** LOGOUT ****" << endl;
                        srv.serverConn->removeUser(sd);
                        srv.serverConn->printOnlineUsers();
                        srv.serverConn->disconnect_host(sd, i);
                        continue;
                    } else {
                        cout << "Invalid command, please retry" << endl;
                        continue;
                    }
                }  
            }
        }
    }

    if(buffer != NULL)
        delete [] buffer;

    return 0;

}

