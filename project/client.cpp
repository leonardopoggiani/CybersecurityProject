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
#include "include/costants.h"
#include "include/client.h"

using namespace std;


string readMessage();
int sendMessage(string message);
void seeOnlineUsers();
void sendRequestToTalk(string username);
void logout();

string menu = "Hi! This is a secure messaging system. \n What do you want to do? \n 1) See online people \n 2) Send a request talk \n 3) Logout \n Choose a valid option -> ";


int main(int argc, char* const argv[]) {

    int command = 0;

    while(1){
        string username;
        cout << menu;
        cin >> command;
        switch(command){
            case 1: 
                cout << "See online users to talk\n" << endl;
                seeOnlineUsers();
                break;
            case 2:
                cout << "Send a request to talk\n" << endl;
                cout << "Type the username -> " << endl;
                getline(cin, username);
                sendRequestToTalk(username);
                break;
            case 3:
                cout << "Logout..\n" << endl;  
                logout();
                break;
            default:
                cout << "Command not recognized" << endl;
                break;
        }
    }
}


string readMessage() {
    string message;
    cout << "Write here your message >> ";
    getline(cin, message);
    if (message.length() > MESSAGE_MAX_SIZE) {
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
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, LOCALHOST.c_str(), &serv_addr.sin_addr)<=0) {
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

}

void seeOnlineUsers(){

}

void sendRequestToTalk(string username){

}

void Client::addNewUser(std::string username) {
    for(std::string onlineUser : userList) {
        if(username.compare(onlineUser) == 0) {
            return;
        }
    }
    userList.push_back(username);
}

void Client::clearUserList() {
    userList.clear();
}

bool Client::isUserOnline(std::string username){
    for(std::string user : userList){
        if(user.compare(username) == 0){
            return true;
        }
    }
    return false;
}