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
    
    EVP_PKEY* pubKeyDH = NULL;
    char* buffer = new char[constants::MAX_MESSAGE_SIZE];
    vector<unsigned char> packet;
    string username;
    string password;
    string to_insert;
    Client clt;
    fd_set fds;
    int maxfd;
    int option = -1;
    string username_to_contact;

    clt.clientConn->make_connection();

    // messaggio di saluto
    int ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
    if (ret == 0) {
        cout << RED << "[LOG] client disconnected " << RESET << endl;
    }

    if( clt.clientConn->checkAck(buffer) ) {
        cout << GREEN << " [LOG] ack received" << RESET << endl;
    } else {
        cerr << RED << "[ERROR] ack not valid" << RESET << endl;
        exit(1);
    }

    cout << GREEN << "Welcome! \n\n" << RESET << endl;
    cout << "Please type your username -> ";
    cin >> username;
    cout << endl;

    clt.clientConn->setUsername(username);

    cout << "Fine! Now insert you password to login" << endl;
    password = readPassword();

    cout << GREEN << "\n**** AUTHENTICATION ****" << RESET << endl;

    if (!authentication(clt, username, password)) {
        cerr << RED << "[ERROR] authentication failed" << RESET << endl;
        exit(1);
    } 
    
    cout << "-----------------------------" << endl << endl;

    while(1) {
        memset(buffer, 0, constants::MAX_MESSAGE_SIZE);
        option = -1;
        cout << menu << endl;   

        maxfd = (clt.clientConn->getMasterFD() > STDIN_FILENO) ? clt.clientConn->getMasterFD() : STDIN_FILENO;
        FD_ZERO(&fds);
        FD_SET(clt.clientConn->getMasterFD(), &fds); 
        FD_SET(STDIN_FILENO, &fds); 
        
        select(maxfd + 1, &fds, NULL, NULL, NULL); 

        if(FD_ISSET(0, &fds)) {  
            cin >> option;
            cin.ignore();
        }

        if(FD_ISSET(clt.clientConn->getMasterFD(), &fds)) {
            ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
            
            if(buffer[0] == constants::REQUEST) {
                cout << GREEN << "\n[LOG] Received request to talk**" << RESET << endl;
                
                packet.resize(ret);
                memcpy(packet.data(), buffer, ret);

                if(receiveRequestToTalk(clt, packet.data(), ret)){
                    vector<unsigned char> decrypted;
                    int peerKeyDHLen = 0;
                    unsigned char* peerKeyDHBuffer = NULL;
                    int peerPubKeyLen = 0;
                    unsigned char* peerPubKeyBuffer = NULL; 
                    EVP_PKEY* peerKeyDH = NULL;
                    EVP_PKEY *sessionDHKey = NULL;
                    
                    packet.clear();
                    packet.resize(constants::MAX_MESSAGE_SIZE);
                    int received_size = receive_message_enc(clt, packet.data(), decrypted);
                    packet.clear();

                    int byte_index = sizeof(char);

                    memcpy(&(peerKeyDHLen), &decrypted.data()[byte_index], sizeof(int));
                    byte_index += sizeof(int);

                    peerKeyDHBuffer = (unsigned char*)malloc(peerKeyDHLen);
                    if(!peerKeyDHBuffer) {
                        cout << RED << "[ERROR] malloc error" << RESET << endl;
                        exit(1);
                    }

                    memcpy(peerKeyDHBuffer, &decrypted.data()[byte_index], peerKeyDHLen);
                    byte_index += peerKeyDHLen;

                    clt.crypto->deserializePublicKey(peerKeyDHBuffer, peerKeyDHLen, peerKeyDH);

                    memcpy(&(peerPubKeyLen), &decrypted.data()[byte_index], sizeof(int));
                    byte_index += sizeof(int);

                    peerPubKeyBuffer = (unsigned char*)malloc(peerPubKeyLen);
                    if(!peerPubKeyBuffer) {
                        cout << RED << "[ERROR] malloc error" << RESET << endl;
                        exit(1);
                    }

                    memcpy(peerPubKeyBuffer, &decrypted.data()[byte_index], peerPubKeyLen);
                    byte_index += peerPubKeyLen;

                    clt.crypto->deserializePublicKey(peerPubKeyBuffer, peerPubKeyLen, clt.clientConn->getMyCurrentChat()->pubkey_2);

                    // Costruire chiave di sessione prvDH
                    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;

                    clt.crypto->secretDerivation(clt.clientConn->getKeyDHBufferTemp(), peerKeyDH, tempBuffer.data());

                    // prima era
                    // clt.crypto->secretDerivation(sessionDHKey, peerKeyDH, tempBuffer.data());
                    // senza fare la keyGeneration, ma quando era inizializzato sessionDHKey?

                    memcpy(clt.clientConn->getMyCurrentChat()->chat_key, tempBuffer.data(), EVP_MD_size(EVP_sha256()));

                    if(!clt.clientConn->getMyCurrentChat()->chat_key) {
                        cout << RED << "[ERROR] malloc error" << RESET << endl;
                        exit(1);    
                    }

                    cout << "---------------------------------------" << endl;
                    cout << "\n-------Chat-------" << endl;
                    cout << "you can insert ':q!' to exit the chat!" << endl;
                    cout << "---------------------------------------" << endl;
                    
                    chat(clt);

                    cout << "------------------" << endl;
                }
            } else {
                cout << RED << "[ERROR] error, disconnecting" << RESET << endl;
                exit(1); 
            }
        }

        switch(option){
            case 1: 
                cout << CYAN << "See online users to talk\n" << RESET << endl;
                packet.clear();
                seeOnlineUsers(clt, packet);
                break;
            case 2:
                cout << CYAN << "Send a request to talk\n" << RESET << endl;
                cout << "Type the username -> " ;
                username_to_contact = readMessage();

                if(username_to_contact.length() == 0){
                    cerr << RED << "[ERROR] No username inserted" << endl;
                    exit(1);
                }

                sendRequestToTalk(clt, username_to_contact, username);
                break;
            case 3:
                cout << RED << "[LOG] Logout\n" << RESET << endl;  
                logout(clt);
                return 0;
            default:
                cout << RED << "[ERROR] Command not recognized " << RESET << endl;
                return 1;
        }
    }
}