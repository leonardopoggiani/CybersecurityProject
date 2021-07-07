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

    int command = 0;
    
    string username;
    string password;
    string to_insert;
    char* buffer = new char[constants::MAX_MESSAGE_SIZE];
    vector<unsigned char> packet;
    vector<unsigned char> command_received;
    Client clt;
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

    cout << "\n**** AUTHENTICATION ****" << endl;

    if (!authentication(clt)) throw runtime_error("Authentication Failed");
        cout << "-----------------------------" << endl << endl;

    while(1) {
        string username_to_contact;
        cout << menu << endl;
        cin >> command;
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 

        switch(command){
            case 1: 
                cout << "See online users to talk\n" << endl;
                clt.clientConn->seeOnlineUsers(command_received);
                break;
            case 2:
                cout << "Send a request to talk\n" << endl;
                cout << "Type the username -> " ;
                username_to_contact = readMessage();

                if(username_to_contact.length() == 0){
                    cerr << "No username inserted" << endl;
                    exit(EXIT_FAILURE);
                }
                clt.clientConn->sendRequestToTalk(command_received, username_to_contact);
                break;
            case 3:
                cout << "Logout..\n" << endl;  
                clt.clientConn->logout(command_received);
                return 0;
            default:
                cout << "Command not recognized" << endl;
                exit(EXIT_FAILURE);
        }
    }

}