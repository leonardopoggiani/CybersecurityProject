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

void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

string readPassword() {
    string password;
    cout << "Insert password: ";
    setStdinEcho(false);
    cin >> password;
    cin.ignore();
    setStdinEcho(true);
    cout << endl;
    return password;
}

int main(int argc, char* const argv[]) {

    int command = 0;
    int ret;
    string username;
    string password;
    string to_insert;
    char* buffer = new char[constants::MAX_MESSAGE_SIZE];
    vector<unsigned char> packet;
    vector<unsigned char> command_received;
    array<unsigned char, NONCE_SIZE> nonceClient;
    Client clt;
    X509 *cert;    
    clt.clientConn->make_connection();
    // messaggio di saluto
    ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
    cout << "must be: Hi, i'm the server | " << buffer << endl;

    packet.push_back('|');
    packet.push_back('1');
    packet.push_back('|');
    cout << "Welcome! Please type your username" << endl;
    cin >> username;

    for(int i = 0 ; i < username.size() ; i++) {
        packet.push_back(username[i]);
    }
    packet.push_back('|');

    cout << "Fine! Now insert you password to chat with others" << endl;
    password = readPassword();
    for(int i = 0 ; i < password.size() ; i++) {
        packet.push_back(password[i]);
    }
    packet.push_back('|');
    
    cout << "to_insert: " << packet.data() << endl;  

    clt.crypto->generateNonce(nonceClient.data());
    for(int i = 0 ; i < nonceClient.size() ; i++) {
        packet.push_back(nonceClient[i]);
    }
    
    cout << "packet: " <<  packet.data() << endl;   

    clt.clientConn->send_message(packet);
    
    //ricevere certificato, da spostare in authentication
    
    ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
    cout << ret << endl;
    cout << "received: "<< buffer << endl;
    
    char* opcode = strtok(buffer, "|");
    int cert_len = atoi(strtok(NULL, "|"));
    cout << cert_len << endl;
    char* certString = strtok(NULL, "|");

    clt.crypto->deserializeCertificate(cert_len, reinterpret_cast<unsigned char*>(certString), cert);
    if(!clt.crypto->verifyCertificate(cert)) {
        throw runtime_error("Certificate not valid.");
    }
    cout << "Server certificate verified" << endl;

    
    //Prova
    //if (!authentication(clt)) throw runtime_error("Authentication Failed");
        //cout << "-----------------------------" << endl << endl;

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
                break;
            default:
                cout << "Command not recognized" << endl;
                exit(EXIT_FAILURE);
        }
    }

}