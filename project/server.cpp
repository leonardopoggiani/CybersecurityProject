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

                        array<unsigned char, MAX_MESSAGE_SIZE> pubKeyClientBuffer;
                        vector<unsigned char> decrypted;
                        vector<unsigned char> encrypted;
                        int keyDHBufferLen = 0;
                        char opCode;
                        unsigned char* keyClientDHBuffer;
                        int byte_index = sizeof(char);

                        srv.crypto->decryptMessage(srv.serverConn->getSessionKey(sd), buffer.data(), ret, decrypted);         

                        memcpy(&keyDHBufferLen, &(decrypted.data()[byte_index]), sizeof(int));
                        byte_index += sizeof(int);

                        keyClientDHBuffer = (unsigned char*)malloc(keyDHBufferLen); 
                        if(keyClientDHBuffer == NULL) {
                            cout << RED << "[ERROR] malloc error" << RESET << endl;
                            exit(1);
                        }   

                        memcpy(keyClientDHBuffer, &(decrypted.data()[byte_index]), keyDHBufferLen);
                        byte_index += keyDHBufferLen;

                        unsigned char* usernameA = NULL;
                        int usernameA_size = 0;
                        vector<userChat*> chatList = srv.serverConn->getActiveChats();
                        int clientB_sd;

                        for(auto chat : chatList) {
                            if(memcmp(srv.serverConn->findUserFromSd(sd).c_str(), chat->username_2, chat->dim_us2) == 0) {
                                usernameA = (unsigned char*) malloc(chat->dim_us2);
                                memcpy(usernameA, chat->username_2, chat->dim_us2);
                                usernameA_size = chat->dim_us2;
                                clientB_sd = chat->sd_1;
                                break;
                            } else if(memcmp(srv.serverConn->findUserFromSd(sd).c_str(), chat->username_1, chat->dim_us1) == 0) {
                                usernameA = (unsigned char*) malloc(chat->dim_us1);
                                memcpy(usernameA, chat->username_1, chat->dim_us1);
                                usernameA_size = chat->dim_us1;
                                clientB_sd = chat->sd_2;
                                break;
                            }
                        }

                        if(!usernameA) {
                            cout << RED << "[ERROR] malloc error" << RESET << endl;
                            exit(1);
                        }

                        std::stringstream filename_stream;
                        std::stringstream username_string;

                        for(int i = 0; i < usernameA_size; i++) {
                            filename_stream << usernameA[i];
                            username_string << usernameA[i];
                        }

                        cout << endl;

                        filename_stream << "_pubkey.pem";

                        string filename = filename_stream.str();

                        string filename_dir = "keys/public/" + filename;
                            
                        FILE* file;
                        file = fopen(filename_dir.c_str(), "r");
                        if(!file) {
                            cerr << RED << "[ERROR] file not found" << RESET << endl;
                            exit(1);
                        }

                        EVP_PKEY *pubkey_client_A = PEM_read_PUBKEY(file, NULL, NULL, NULL);
                        if(!pubkey_client_A){
                            fclose(file);
                            cerr << RED << "[ERROR] error reading pubkey" << RESET << endl;
                            exit(1);
                        }

                        // Serializzare chiave pubblica
                        int pubKeyBufferLen = srv.crypto->serializePublicKey(pubkey_client_A, pubKeyClientBuffer.data());

                        int dim = sizeof(char) + sizeof(int) + keyDHBufferLen + sizeof(int) + pubKeyBufferLen;
                        byte_index = 0;

                        unsigned char* message = (unsigned char*)malloc(dim);

                        memcpy(&(message[byte_index]), &constants::ACCEPTED, sizeof(char));
                        byte_index += sizeof(char);

                        memcpy(&(message[byte_index]), &keyDHBufferLen, sizeof(int));
                        byte_index += sizeof(int);

                        memcpy(&(message[byte_index]), keyClientDHBuffer, keyDHBufferLen);
                        byte_index += keyDHBufferLen;

                        memcpy(&(message[byte_index]), &pubKeyBufferLen, sizeof(int));
                        byte_index += sizeof(int);

                        memcpy(&(message[byte_index]), pubKeyClientBuffer.data(), pubKeyBufferLen);
                        byte_index += pubKeyBufferLen;

                        srv.serverConn->generateIV();
                        ret = send_message_enc_srv(srv.crypto, clientB_sd, srv.serverConn->getSessionKey(clientB_sd), srv.serverConn->getIV(), message, byte_index, encrypted);
                        
                    } else if(buffer[0] == constants::CHAT) {
                        cout << GREEN << "\n**** CHAT ****" << RESET << endl;

                        if (!chatting(srv, sd, buffer.data(), ret)) {
                            cerr << RED << "Chat failed on Server" << RESET << endl;
                            exit(1);
                        };
                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::LOGOUT) {

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

