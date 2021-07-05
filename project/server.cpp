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

    int ret;
    char* buffer = new char[constants::MAX_MESSAGE_SIZE];
    vector<unsigned char> buffToSend;
    vector<unsigned char> vectorBuffer;
    array<unsigned char,constants::MAX_MESSAGE_SIZE> certificate_to_send;
    unsigned char* cert_buf= NULL;
    int cert_size = 0;
    
    int buffToSendLen;
    Server srv;
    X509 *cert;
  
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

                    if(ret == 0) {
                        cout << "removing user 1" << endl;
                        srv.serverConn->removeUser(sd);
                        srv.serverConn->printOnlineUsers();
                        srv.serverConn->disconnect_host(sd, i);                      
                        continue;
                    }

                    char* opcode = strtok(buffer, "|");
                    char* username = strtok(NULL, "|");
                    char* password = strtok(NULL, "|");
                    char* nonce = strtok(NULL, "|");

                    // controllare che username password e nonce non abbiamo la barra nel mezzo, altrimenti sono problemi
                    cout << "opcode: " << opcode << ",username: " << username << ",password: " << password << endl;


                    if(buffer[1] == '1') {
                        cout << "\n**** AUTHENTICATION ****" << endl;

                        string end = "_pubkey.pem";
                        string filename = username + end;

                        FILE* file;
                        string filename_dir = "keys/public/" + filename;
                        cout << "filename " << filename_dir.c_str() << endl;
                        
                        file = fopen(filename_dir.c_str(), "r");
                        if(!file)
                            throw runtime_error("An error occurred, the file doesn't exist.");

                        EVP_PKEY *pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
                        if(!pubkey){
                            fclose(file);
                            throw runtime_error("An error occurred while reading the public key.");
                        }

                        srv.serverConn->insertUser(username, sd);
                        srv.serverConn->printOnlineUsers();
                        
                        //Send certificate, da spostare in authentication
                        srv.crypto->loadCertificate(cert, "ChatAppServer_cert");

                        cert_size= i2d_X509(cert, &cert_buf);        
                        if(cert_size< 0) { throw runtime_error("An error occurred during the reading of the certificate."); }
                        
                        uint16_t lmsg = htons(cert_size);

                        ret = send(sd, (void*) &lmsg, sizeof(uint16_t), 0);
                        send(sd, cert_buf, cert_size, 0);
                        /*buffToSendLen = srv.crypto->serializeCertificate(cert, certificate_to_send.data());
                        
                        buffToSend.push_back('|');
                        buffToSend.push_back('1');
                        buffToSend.push_back('|');
                        
                        for(unsigned int i = 0; i < buffToSendLen; i++) {
                            buffToSend.push_back(certificate_to_send[i]);
                        }

                        uint16_t lmsg = htons(buffToSendLen);

                        ret = send(sd, (void*) &lmsg, sizeof(uint16_t), 0);
                        if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                            perror("Send Error");
                            throw runtime_error("Send failed");
                        }   

                        srv.serverConn->send_message(buffToSend,sd);
                        */
                        
                    }  /*else if(command.compare("2") == 0) {
                        cout << "\n**** ONLINE USERS REQUEST ****" << endl;
                    }else if(command.compare("3") == 0) {
                        cout << "\n**** REQUEST TO TALK****" << endl;
                    }else if(command.compare("4") == 0) {
                        cout << "\n**** CHAT ****" << endl;
                    } */ else if(buffer[1] == '5') {
                        cout << "\n**** LOGOUT ****" << endl;
                        srv.serverConn->removeUser(sd);
                        srv.serverConn->printOnlineUsers();
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

