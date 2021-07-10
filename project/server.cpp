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

struct chat {
    unsigned char* username_1;
    int sd_1;
    unsigned char* username_2;
    int sd_2;

    chat(unsigned char* us1, int s1, unsigned char* us2, int s2) {
        username_1 = us1;
        username_2 = us2;
        sd_1 = s1;
        sd_2 = s2;
    }
};

vector<chat*> activeChat;

int main(int argc, char* const argv[]) {

    int ret = 0;
    unsigned char* buffer = new unsigned char[constants::MAX_MESSAGE_SIZE];
    Server srv;
  
    while(1) {

        memset(buffer, 0, sizeof(buffer));

        cout << "--- waiting for connections ---" << endl;

        srv.serverConn->initSet();
        srv.serverConn->selectActivity();

        if(srv.serverConn->isFDSet(srv.serverConn->getMasterFD())) {
            srv.serverConn->accept_connection();
        } else {    

            for(unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  

                int sd = srv.serverConn->getClient(i);

                if (recv(sd, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0) {
                    srv.serverConn->disconnect_host(sd, i);
                    srv.serverConn->printOnlineUsers();
                    continue;
                }

                if (srv.serverConn->isFDSet(sd)) {              
                    ret = srv.serverConn->receive_message(sd, buffer);

                    if(ret == 0) {
                        srv.serverConn->disconnect_host(sd, i);  
                        srv.serverConn->printOnlineUsers();
                        continue;
                    }

                    if(buffer[0] == constants::AUTH) {
                        cout << "\n**** AUTHENTICATION ****" << endl;
                      
                        if (!authentication(srv, sd, buffer)) throw runtime_error("Authentication failed on Server");
                        cout << "-----------------------------" << endl << endl;

                    } else if(buffer[0] == constants::ONLINE) {
                        cout << "\n**** ONLINE USERS REQUEST ****" << endl;

                        if (!seeOnlineUsers(srv, sd, buffer)) throw runtime_error("Online Users request failed on Server");
                        cout << "-----------------------------" << endl << endl;

                    }else if(buffer[0] == constants::REQUEST) {
                        cout << "\n**** REQUEST TO TALK****" << endl;

                        if (!requestToTalk(srv, sd, buffer)) throw runtime_error("Request to talk failed on Server");
                        cout << "-----------------------------" << endl << endl;

                    }else if(buffer[0] == constants::START_CHAT) {
                        cout << "\n**** START CHAT ****" << endl;

                        char opCode;
                        int byte_index = 0;
                        unsigned char* username_1;
                        unsigned char* username_2;
                        int username_1_size = 0;
                        int username_2_size = 0;

                        memcpy(&(opCode), &buffer[byte_index], sizeof(char));
                        byte_index += sizeof(char);

                        memcpy(&(username_1_size), &buffer[byte_index], sizeof(int));
                        byte_index += sizeof(int);

                        username_1 = (unsigned char*)malloc(username_1_size);
                        memcpy(username_1, &buffer[byte_index], username_1_size);
                        byte_index += username_1_size;

                        memcpy(&(username_2_size), &buffer[byte_index], sizeof(int));
                        byte_index += sizeof(int);

                        username_2 = (unsigned char*)malloc(username_2_size);
                        memcpy(username_2, &buffer[byte_index], username_2_size);
                        byte_index += username_2_size;

                        int sd_1 = 0;
                        int sd_2 = 0;

                        vector<users> users_logged_in = srv.serverConn->getUsersList();
                        for(auto user : users_logged_in) {
                            if(memcmp(user.username.c_str(), username_1, username_1_size) == 0) {
                                cout << "first user " << user.sd << endl;
                                sd_1 = user.sd;
                            }

                            if(memcmp(user.username.c_str(), username_2, username_2_size) == 0) {
                                cout << "second user " << user.sd << endl;
                                sd_2 = user.sd;
                            }
                        }

                        chat *new_chat = new chat(username_1, sd_1, username_2, sd_2);
                        activeChat.push_back(new_chat);

                        byte_index = 0;

                        int dim_m1 = username_2_size + sizeof(int);
                        unsigned char* m1 = (unsigned char*) malloc(dim_m1);
                        memcpy(&(m1[byte_index]), &username_2_size, sizeof(int));
                        byte_index += sizeof(int);

                        memcpy(&(m1[byte_index]), username_2, username_2_size);
                        byte_index += username_2_size;

                        byte_index = 0;

                        int dim_m2 = username_2_size + sizeof(int);
                        unsigned char* m2 = (unsigned char*) malloc(dim_m2);
                        memcpy(&(m2[byte_index]), &username_1_size, sizeof(int));
                        byte_index += sizeof(int);

                        memcpy(&(m2[byte_index]), username_1, username_1_size);
                        byte_index += username_1_size;

                        srv.serverConn->send_message(m1, sd_1, dim_m1);
                        cout << "inviato il primo: size " << username_1_size << "username1: " << username_1 << endl;
                        srv.serverConn->send_message(m2, sd_2, dim_m2);
                        cout << "inviato il secondo: size " << username_2_size << "username2: " << username_2 << endl;

                    } else if(buffer[0] == constants::CHAT) {
                        cout << "\n**** CHAT ****" << endl;


                    } else if(buffer[0] == constants::LOGOUT) {
                        cout << "\n**** LOGOUT ****" << endl;
                        srv.serverConn->disconnect_host(sd, i);
                        srv.serverConn->printOnlineUsers();
                        continue;
                    } else {
                        cout << "Invalid command, please retry" << endl;
                        continue;
                    }
                }  
            }
        }
    }

    if(buffer != NULL)
        delete [] buffer;

    return 0;

}

