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
#include "include/utils.h"

using namespace std;

const string menu = "Hi! This is a secure messaging system. \n What do you want to do? \n 1) See online people \n 2) Send a request talk \n 3) Logout \n Choose a valid option -> ";

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
    if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
        perror("Send Error");
        throw runtime_error("Send failed");
    }   

    if( clt.clientConn->checkAck(buffer) ) {
        cout << "ack received" << endl;
    }

    cout << "Welcome! \nPlease type your username -> ";
    cin >> username;
    cout << endl;

    //cout << "Fine! Now insert you password to chat with others" << endl;
    //password = readPassword();

    cout << "\n**** AUTHENTICATION ****" << endl;

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
            clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
            
            if(buffer[0] == constants::FORWARD) {
                cout << "\n-------Received request to talk-------" << endl;
                if(receiveRequestToTalk(clt, buffer)){
                    cout << "---------------------------------------" << endl;
                    cout << "\n-------Chat-------" << endl;
                    
                    clt.clientConn->chat();

                    cout << "------------------" << endl;
                }
            }
        }

        switch(option){
            case 1: 
                cout << "See online users to talk\n" << endl;
                clt.clientConn->seeOnlineUsers();
                break;
            case 2:
                cout << "Send a request to talk\n" << endl;
                cout << "Type the username -> " ;
                username_to_contact = readMessage();

                if(username_to_contact.length() == 0){
                    cerr << "No username inserted" << endl;
                    return 1;
                }
                clt.clientConn->sendRequestToTalk(username_to_contact, username);
                break;
            case 3:
                cout << "Logout..\n" << endl;  
                clt.clientConn->logout();
                return 0;
            default:
                cout << "Command not recognized" << endl;
                return 1;
        }
    }

    free(buffer);

}