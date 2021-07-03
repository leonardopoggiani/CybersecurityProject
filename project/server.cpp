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
#include "include/server.h"
#include "include/constants.h"

using namespace std;

int main(int argc, char* const argv[]) {

    int ret;
    char* buffer = new char[constants::MAX_MESSAGE_SIZE];
    Server srv;
  
    while(1) {

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
                    continue;
                }

                if (srv.serverConn->isFDSet(sd)) {              
                    ret = srv.serverConn->receive_message(sd, buffer);
                    cout << "Username and password: " << buffer << endl;


                    char* opcode = strtok(buffer, "|");
                    char* username = strtok(NULL, "|");
                    char* password_length = strtok(NULL, "|");
                    char* password = strtok(NULL, "|");

                    cout << "opcode: " << opcode << ",username: " << username << ",password: " << password << endl;

                    if(buffer[1] == '1') {
                        cout << "\n**** AUTHENTICATION ****" << endl;

                        string end = "_prvkey.pem";
                        string filename = username + end;

                        FILE* file;
                        string filename_dir = "keys/private/" + filename;
                        cout << "filename " << filename_dir.c_str() << endl;
                        
                        file = fopen(filename_dir.c_str(), "r");
                        if(!file)
                            throw runtime_error("An error occurred, the file doesn't exist.");

                        EVP_PKEY *prvKey = PEM_read_PrivateKey(file, NULL, NULL, password);
                        if(!prvKey){
                            fclose(file);
                            throw runtime_error("An error occurred while reading the private key.");
                        }

                        cout << "ok" << endl;
                    }  /*else if(command.compare("2") == 0) {
                        cout << "\n**** ONLINE USERS REQUEST ****" << endl;
                    }else if(command.compare("3") == 0) {
                        cout << "\n**** REQUEST TO TALK****" << endl;
                    }else if(command.compare("4") == 0) {
                        cout << "\n**** CHAT ****" << endl;
                    } */ else if(buffer[1] == '5') {
                        cout << "\n**** LOGOUT ****" << endl;
                        srv.serverConn->disconnect_host(sd, i);
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

