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

    int ret = 0;
    Server srv;
    array<unsigned char, constants::MAX_MESSAGE_SIZE> buffer;
    vector<unsigned char> received;
  
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
                      
                        if (!authentication(srv, sd, buffer.data())) {
                            cerr << RED << "Authentication failed on Server" << RESET << endl;
                            exit(1);
                        };

                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::ONLINE) {
                        cout << GREEN << "\n**** ONLINE USERS REQUEST ****" << RESET << endl;

                        if (!seeOnlineUsers(srv, sd, received)) {
                            cerr << RED << "Online user request failed on Server" << RESET << endl;
                            exit(1);
                        };
                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::REQUEST) {
                        cout << GREEN << "\n**** REQUEST TO TALK****" << RESET << endl;

                        if (!requestToTalk(srv, sd, buffer.data(), ret)){
                            cerr << RED << "Request to talk failed on Server" << RESET << endl;
                            exit(1);
                        };
                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::ACCEPTED) {
                        
                        cout << GREEN << "\n**** START CHAT ****" << RESET << endl;
                        cout << BOLDGREEN << "[LOG] Chat started! " << RESET << endl;

                        startingChat(srv, sd, buffer, ret);
                        
                    } else if(buffer[0] == constants::CHAT) {
                        cout << GREEN << "\n**** CHAT ****" << RESET << endl;

                        if (!chatting(srv, sd, buffer.data(), ret)) {
                            cerr << RED << "Chat failed on Server" << RESET << endl;
                            exit(1);
                        };
                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::REFUSED) {
                        cout << GREEN << "\n**** CLOSING CHAT ****" << RESET << endl;

                        if (!closingChat(srv, sd, buffer.data(), ret)){
                            cerr << RED << "Request to close chat failed on Server" << RESET << endl;
                            exit(1);
                        };
                    } 
                    else if(buffer[0] == constants::LOGOUT) {

                        cout << YELLOW << "\n[LOG] LOGOUT " << RESET << endl;

                        srv.serverConn->disconnect_host(sd, i);
                        srv.serverConn->printOnlineUsers();
                        continue;
                        
                    } else {
                        cout << RED << "[ERROR] Invalid command { " << buffer[0] << " } , please retry" << RESET << endl;
                        continue;
                    }
                }  
            }
        }
    }

    received.clear();
    return 0;
}

