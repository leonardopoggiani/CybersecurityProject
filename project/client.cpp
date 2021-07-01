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
    Client clt;
    int command = 0;
    int ret;

    clientConnection *client_connection = new clientConnection();
    ret = client_connection->connection();

    if( ret != 0 ){
        cerr << "--- connection failed ---" << endl;
        exit(EXIT_FAILURE);
    } else {
        cout << "--- connection done ---" << endl;
    }

    while(1){
        string username;
        //cout << menu;
        //cin >> command;
        //cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
        if (!authentication(clt)) throw runtime_error("Authentication Failed");
        cout << "-----------------------------" << endl << endl;


        /*switch(command){
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
                break;
        }*/
    }
}

string readMessage() {
    string message;
    getline(cin, message);
    if (message.length() > constants::MAX_MESSAGE_SIZE) {
        cerr << "Error: the message must be loger than " << endl;
        exit(EXIT_FAILURE);
    }
    return message;
}

int sendMessage(string message) {
    int sock = 0, valread;
    struct sockaddr_in serv_addr;

    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\n Socket creation error \n" << endl;
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(constants::PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, constants::LOCALHOST, &serv_addr.sin_addr)<=0) {
        cerr << "\nInvalid address/ Address not supported \n" << endl;
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "\nConnection Failed \n" << endl;
        return -1;
    }
    send(sock , message.c_str() , message.length() , 0 );
    valread = read( sock , buffer, 1024);
    cout << buffer << endl;
}

void logout(){
    sendMessage("logout");

}

void seeOnlineUsers(){
    sendMessage("Let me see online users");
}

void sendRequestToTalk(string username){  
    sendMessage("Let me talk with " + username);
}

void Client::addNewUser(std::string username) {
    for(std::string onlineUser : userList) {
        if(username.compare(onlineUser) == 0) {
            return;
        }
    }
}
