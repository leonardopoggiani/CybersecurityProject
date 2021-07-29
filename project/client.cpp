#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <termios.h>
#include "include/client.h"

using namespace std;

const string menu = "Hi! This is a secure messaging system. \n What do you want to do? \n 1) See online people \n 2) Send a request talk \n 3) Logout \n\n Choose a valid option -> ";

int main(int argc, char* const argv[]) {
    
    string username;
    string password;
    string to_insert;
    char* buffer = new char[constants::MAX_MESSAGE_SIZE];
    vector<unsigned char> packet;
    Client clt;
    fd_set fds;
    int maxfd;
    int option = -1;
    bool disconnect = false;
    string username_to_contact;

    clt.clientConn->make_connection();

    // messaggio di saluto
    int ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
    if(ret == 0) {
        cout << RED << "**client disconnected**" << RESET << endl;
    }

    if( clt.clientConn->checkAck(buffer) ) {
        cout << GREEN << "ack received" << RESET << endl;
    }

    cout << GREEN << "Welcome! \n\n" << RESET << endl;
    cout << "Please type your username -> ";
    cin >> username;
    cout << endl;

    cout << "Fine! Now insert you password to chat with others" << endl;
    password = readPassword();

    cout << GREEN << "\n**** AUTHENTICATION ****" << RESET << endl;

    if (!authentication(clt,username,password)) throw runtime_error("Authentication Failed");
        cout << "-----------------------------" << endl << endl;

    while(1) {
        option = -1;
        cout << menu << endl;   

        maxfd = (clt.clientConn->getMasterFD() > STDIN_FILENO) ? clt.clientConn->getMasterFD() : STDIN_FILENO;
        FD_ZERO(&fds);
        FD_SET(clt.clientConn->getMasterFD(), &fds); 
        FD_SET(STDIN_FILENO, &fds); 
        
        select(maxfd+1, &fds, NULL, NULL, NULL); 

        if(FD_ISSET(0, &fds)) {  
            cin >> option;
            cin.ignore();
        }

        if(FD_ISSET(clt.clientConn->getMasterFD(), &fds)) {
            ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
            if(ret == 0) {
                cout << RED << "**client disconnected**" << RESET << endl;
            }
            
            if(buffer[0] == constants::REQUEST) {
                cout << GREEN << "\n**Received request to talk**" << RESET << endl;
                if(receiveRequestToTalk(clt, buffer)){
                    cout << "---------------------------------------" << endl;
                    cout << "\n-------Chat-------" << endl;
                    
                    chat(clt);

                    cout << "------------------" << endl;
                }
            }
        }

        switch(option){
            case 1: 
                cout << CYAN << "See online users to talk\n" << RESET << endl;
                seeOnlineUsers(clt, packet);
                break;
            case 2:
                cout << CYAN << "Send a request to talk\n" << RESET << endl;
                cout << "Type the username -> " ;
                username_to_contact = readMessage();

                if(username_to_contact.length() == 0){
                    cerr << "No username inserted" << endl;
                    return 1;
                }
                sendRequestToTalk(clt, username_to_contact, username);
                break;
            case 3:
                cout << RED << "Logout..\n" << RESET << endl;  
                logout(clt);
                return 0;
            default:
                cout << RED << "**Command not recognized**" << RESET << endl;
                return 1;
        }
    }

    free(buffer);

}