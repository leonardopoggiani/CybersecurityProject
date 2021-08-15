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

array<unsigned char, constants::MAX_MESSAGE_SIZE> buffer;
vector<unsigned char> received;

int main(int argc, char* const argv[]) {

    int ret = 0;
    Server srv;
  
    while(1) {

        cout << GREEN << "--- waiting for connections ---" << RESET << endl;

        srv.serverConn->initSet();
        srv.serverConn->selectActivity();

        if(srv.serverConn->isFDSet(srv.serverConn->getMasterFD())) {
            srv.serverConn->accept_connection();
        } else {    

            for(unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  

                int sd = srv.serverConn->getClient(i);

                if (recv(sd, buffer.data(), sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0) {
                    srv.serverConn->disconnect_host(sd, i);
                    srv.serverConn->printOnlineUsers();
                    continue;
                }

                if (srv.serverConn->isFDSet(sd)) {              
                    ret = srv.serverConn->receive_message(sd, buffer.data());

                    if(ret == 0) {
                        srv.serverConn->disconnect_host(sd, i);  
                        srv.serverConn->printOnlineUsers();
                        continue;
                    }

                    if(buffer[0] == constants::AUTH) {
                        cout << GREEN << "\n**** AUTHENTICATION ****" << RESET << endl;
                      
                        if (!authentication(srv, sd, buffer.data())) throw runtime_error("Authentication failed on Server");
                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::ONLINE) {
                        cout << GREEN << "\n**** ONLINE USERS REQUEST ****" << RESET << endl;

                        if (!seeOnlineUsers(srv, sd, received)) throw runtime_error("Online Users request failed on Server");
                        cout << "-----------------------------" << endl << endl;

                    }else if(buffer[0] == constants::REQUEST) {
                        cout << GREEN << "\n**** REQUEST TO TALK****" << RESET << endl;

                        if (!requestToTalk(srv, sd, buffer.data(), ret)) throw runtime_error("Request to talk failed on Server");
                        cout << "-----------------------------" << endl << endl;

                    }else if(buffer[0] == constants::ACCEPTED) {
                        
                        cout << GREEN << "\n**** START CHAT ****" << RESET << endl;
                        cout << BOLDGREEN << "Chat started! " << RESET << endl;

                    } else if(buffer[0] == constants::CHAT) {
                        cout << GREEN << "\n**** CHAT ****" << RESET << endl;

                        if (!chatting(srv, sd, buffer.data(), ret)) throw runtime_error("Chatting failed on Server");
                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::LOGOUT) {

                        cout << YELLOW << "\n**** LOGOUT ****" << RESET << endl;

                        srv.serverConn->disconnect_host(sd, i);
                        srv.serverConn->printOnlineUsers();
                        continue;
                        
                    } else {
                        cout << RED << "**Invalid command { " << buffer[0] << " } , please retry**" << RESET << endl;
                        continue;
                    }
                }  
            }
        }
    }

    return 0;

}

