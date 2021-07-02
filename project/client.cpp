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
#include "include/client.h"
#include "include/utils.h"

using namespace std;

const string menu = "Hi! This is a secure messaging system. \n What do you want to do? \n 1) See online people \n 2) Send a request talk \n 3) Logout \n Choose a valid option -> ";

int main(int argc, char* const argv[]) {

    int command = 0;
    int ret;

    clientConnection *client_connection = new clientConnection();
    client_connection->make_connection();

    //if (!authentication(clt)) throw runtime_error("Authentication Failed");
        //cout << "-----------------------------" << endl << endl;

    while(1){
        string username;
        cout << menu;
        cin >> command;
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 

        switch(command){
            case 1: 
                cout << "See online users to talk\n" << endl;
                client_connection->seeOnlineUsers();
                break;
            case 2:
                cout << "Send a request to talk\n" << endl;
                cout << "Type the username -> " ;
                username = readMessage();

                if(username.length() == 0){
                    cerr << "No username inserted" << endl;
                    exit(EXIT_FAILURE);
                }
                client_connection->sendRequestToTalk(username);
                break;
            case 3:
                cout << "Logout..\n" << endl;  
                client_connection->logout();
                break;
            default:
                cout << "Command not recognized" << endl;
                exit(EXIT_FAILURE);
        }
    }
}
