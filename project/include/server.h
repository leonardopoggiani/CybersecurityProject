#include <limits>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <iostream>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>   
#include <sys/time.h> 
#include <errno.h>
#include <time.h>      
#include "constants.h"
#include "client.h"
#include "connection.h"


using namespace std;


class serverConnection : public clientConnection{

    struct users {
        string username;
        unsigned int sd;

        users(string us,unsigned int s) {
            username = us;
            sd = s;
        }
    };

    vector<users> users_logged_in;

    private:
        int client_socket[constants::MAX_CLIENTS];
        fd_set readfds;
        int max_sd;
        int sd;
        int activity;
        int addrlen;
        int port;
        char buffer[1025];

    public:

        serverConnection():clientConnection() {
            port = 8888;
            for (size_t i = 0; i < constants::MAX_CLIENTS; i++) {
                client_socket[i] = 0;
            }

            address.sin_addr.s_addr = INADDR_ANY;

            serverBind();
            listenForConnections();
        }

        void serverBind() {
            if (::bind(master_fd, (struct sockaddr *)&address, sizeof(address)) < 0) 
                throw runtime_error("Error in binding");  
            cout << "Listening on port: " <<  port << endl;  
        }

        void listenForConnections() {
            if (listen(master_fd, 3) < 0)
                throw runtime_error("Error in listening");
        }

        ~serverConnection() {
            // Chiude il socket
            close(master_fd);
            cout << "--- connection closed ---" << endl;
        }
        
        void initSet() {
            FD_ZERO(&readfds);  
            FD_SET(master_fd, &readfds);  
            max_sd = master_fd;  
            
            for ( int i = 0 ; i < constants::MAX_CLIENTS; i++)  {  
                sd = client_socket[i];  
                if(sd > 0) FD_SET( sd , &readfds);  
                if(sd > max_sd) max_sd = sd;  
            }

            addrlen = sizeof(address);
        }

        bool isFDSet(int fd) {
            return FD_ISSET(fd, &readfds);
        }

        int getClient(unsigned int i) {
            if (i > constants::MAX_CLIENTS - 1)
                throw runtime_error("Max clients exceeds");
            return client_socket[i];
        }

        void selectActivity() {
            activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
            if ((activity < 0) && (errno!=EINTR))
                throw runtime_error("Error in the select function"); 
        }

        void accept_connection() {
            int new_socket;
            string message;

            try {
                if ((new_socket = accept(master_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
                    perror("accept");  
                    throw runtime_error("Failure on accept");
                }  

                cout << "********************************" << endl;
                cout << "New client online" << endl;
                cout << "Socket fd is \t" << new_socket << endl;
                cout << "IP: \t\t" <<  inet_ntoa(address.sin_addr) << endl;
                cout << "Port: \t\t" << ntohs(address.sin_port) << endl;
                cout << "********************************" << endl << endl;
                
                time_t rawtime;
                char buffer [255];

                time (&rawtime);
                sprintf(buffer,"ack_%s",ctime(&rawtime) );

                char *p = buffer;
                for (; *p; ++p)
                {
                    if (*p == ' ')
                        *p = '_';
                }

                if(send(new_socket,buffer, strlen(buffer), 0) != strlen(buffer))  
                    throw runtime_error("Error sending the ack message"); 

                for (unsigned int i = 0; i < constants::MAX_CLIENTS; i++) {  
                    if(client_socket[i] == 0)  {  
                        client_socket[i] = new_socket;  
                        break;  
                    } 
                }  
            } catch(const exception& e) {
                throw;
            }
        } 

        void disconnect_host(int sd, unsigned int i) {
            getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);

            cout << "\n **** Client is leaving ****" << endl;
            cout << "IP: \t\t" << inet_ntoa(address.sin_addr) << endl;
            cout << "Port: \t\t" << ntohs(address.sin_port) << endl;
            cout << "**************************" << endl << endl;

            close(sd);  
            client_socket[i] = 0;
        }
        
        void insertUser(string username, int sd){
            if(users_logged_in.size() + 1 < constants::MAX_CLIENTS) {
                users* new_user = new users(username,sd);
                users_logged_in.push_back(*new_user);
            } else  {
                cerr << "Maximum number of online users reached" << endl;
                return;
            }
        }

        void removeUser(int sd) {
            cout << " removing user " << endl;
            for(int i = 0; i < users_logged_in.size(); i++) {
                if(users_logged_in[i].sd == sd){
                    users_logged_in.erase(users_logged_in.begin() + i);
                    cout << "removed user" << endl;

                    return;
                }
            }

            cout << "no user found" << endl;
        }

        void printOnlineUsers(){
            if( users_logged_in.size() == 0 ){
                cout << "no users online" << endl;
                return;
            }

            for(auto user : users_logged_in){
                cout << user.username << " | ";
            }
            cout << endl;
        }

        void send_message(vector<unsigned char> message, int sd) {
            int ret;

            if (message.size() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }
            
            do {
                ret = send(sd, &message[0], message.size(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                }   
            } while (ret != (int) message.size());

            cout << "send riuscita: " << message.size() << endl;
        }

        void send_message(string message, int sd) {
            int ret;

            if (message.length() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }

            do {
                ret = send(sd, message.c_str(), message.length(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                }   
            } while (ret != (int) message.length());
        }

        void send_message(unsigned char* message, int sd, int dim) {
            int ret;
            
            do {
                ret = send(sd, &message[0], dim, 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                }   
            } while (ret != dim);

        }
};

struct Server {
    serverConnection *serverConn;
    CryptoOperation *crypto;

    Server() {
        serverConn = new serverConnection();
        crypto = new CryptoOperation();
    }
};

bool authentication(Server &srv, int sd, unsigned char* buffer) {
    vector<unsigned char> packet;
    vector<unsigned char> signature;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    array<unsigned char, NONCE_SIZE> nonceServer;
    array<unsigned char, NONCE_SIZE> nonceClient;
    unsigned int tempBufferLen;
    unsigned char* cert_buf= NULL;
    EVP_PKEY *pubKeyClient = NULL;
    EVP_PKEY *prvKeyServer = NULL;
    X509 *cert;
    bool ret;

    int byte_index = 0;    

    char opCode;
    int username_size;
    int password_size;
    char* username;
    char* password;
    unsigned char* nonce = (unsigned char*)malloc(constants::NONCE_SIZE);

    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(username_size), &buffer[byte_index],sizeof(int));
    byte_index += sizeof(int);

    username = (char*)malloc(username_size);
    memcpy(username, &buffer[byte_index], username_size);
    byte_index += username_size;

    memcpy(&(password_size), &buffer[byte_index],sizeof(int));
    byte_index += sizeof(int);

    password = (char*)malloc(password_size);
    memcpy(password, &buffer[byte_index], password_size);
    byte_index += password_size;

    memcpy(nonce, &buffer[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

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
                         
    //Send packet with certificate

    srv.crypto->generateNonce(nonceServer.data());

    srv.crypto->loadCertificate(cert, "ChatAppServer_cert");

    int cert_size = i2d_X509(cert, &cert_buf);        
    if(cert_size< 0) { 
        throw runtime_error("An error occurred during the reading of the certificate."); 
    }

    // srv.serverConn->send_message(packet,sd);  
    cout << "inizio invio certificato" << endl;

    int byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + cert_size + nonceServer.size();
    cout << "dim: " << dim << endl;
    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &cert_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), &cert_buf[0], cert_size);
    byte_index += cert_size;

    memcpy(&(message[byte_index]), nonceServer.data(), nonceServer.size());
    byte_index += nonceServer.size();

    srv.serverConn->send_message(message,sd,dim);

    return true;   
}
