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

struct users {
    string username;
    int sd;

    users(string us, int s) {
        username = us;
        sd = s;
    }
};

class serverConnection : public clientConnection {

    private:
        int client_socket[constants::MAX_CLIENTS];
        fd_set readfds;
        int max_sd;
        int sd;
        int activity;
        int addrlen;
        int port;

        vector<users> users_logged_in;

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

                string buffer = "ack";

                if(send(new_socket, buffer.c_str(), buffer.size(), 0) != (ssize_t) buffer.size())  
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
            removeUser(sd);
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
            for(int i = 0; i < (int) users_logged_in.size(); i++) {
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

        vector<users> getUsersList() {
            return users_logged_in;
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
    array<unsigned char, NONCE_SIZE> nonceServer;
    unsigned char* message_wsign= NULL;
    unsigned char* cert_buf= NULL;
    X509 *cert;
    unsigned int pubKeyDHBufferLen;
    EVP_PKEY *prvKeyDHServer = NULL;
    EVP_PKEY *pubKeyDHClient = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    unsigned int sgnt_size=*(unsigned int*)buffer;
	sgnt_size+=sizeof(unsigned int);
    unsigned int message_size = *(unsigned int*)buffer;
    int byte_index = 0;    
    char opCode;
   
    unsigned char* username;
    unsigned char* signature;
    unsigned char* nonce = (unsigned char*)malloc(constants::NONCE_SIZE);

    int username_size = 0;
    int signature_size = 0;
    
    byte_index = 0;
    
    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(username_size), &buffer[byte_index],sizeof(int));
    byte_index += sizeof(int);

    username = (unsigned char*)malloc(username_size);
    memcpy(username, &buffer[byte_index], username_size);
    byte_index += username_size;

    memcpy(nonce, &buffer[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(signature_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    memcpy(signature, &buffer[byte_index], signature_size);
    byte_index += signature_size;

    std::stringstream filename_stream;
    std::stringstream username_string;

    for(int i = 0; i < username_size; i++) {
        filename_stream << username[i];
        username_string << username[i];
    }

    filename_stream << "_pubkey.pem";

    string filename = filename_stream.str();  // The resulting string

    string filename_dir = "keys/public/" + filename;
        
    FILE* file;
    file = fopen(filename_dir.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");

    FILE* file;
    file = fopen("./keys/public/leonardo_pubkey.pem", "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");

    EVP_PKEY *pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubkey){
        fclose(file);
        throw runtime_error("An error occurred while reading the public key.");
    }

    unsigned char* clear_buf = (unsigned char*)malloc(sizeof(char));

    memcpy(clear_buf, &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    int sign_size = 0;
    memcpy(&sign_size, &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* sign = (unsigned char*)malloc(sign_size);
    memcpy(sign, &buffer[byte_index], sign_size);
    byte_index += sign_size;
 
    //NON VA
    unsigned int verify = srv.crypto->digsign_verify(sign, sign_size, clear_buf, sizeof(int), pubkey);
    if(verify<0){cerr<<"establishSession: invalid signature!"; return false;}
    
    //srv.serverConn->insertUser(username_string.str(), sd);
    srv.serverConn->printOnlineUsers();
                         
    //Send packet with certificate

    srv.crypto->generateNonce(nonceServer.data());

    srv.crypto->loadCertificate(cert, "ChatAppServer_cert");

    int cert_size = i2d_X509(cert, &cert_buf);        
    if(cert_size< 0) { 
        throw runtime_error("An error occurred during the reading of the certificate."); 
    }

    srv.crypto->keyGeneration(prvKeyDHServer);
    pubKeyDHBufferLen = srv.crypto->serializePublicKey(prvKeyDHServer, pubKeyDHBuffer.data());

    byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + cert_size + constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferLen;
    cout << "dim: " << dim << endl;
    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &cert_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), &cert_buf[0], cert_size);
    byte_index += cert_size;

    memcpy(&(message[byte_index]), nonceServer.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(message[byte_index]), &pubKeyDHBufferLen, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), pubKeyDHBuffer.data(), pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;

    srv.serverConn->send_message(message,sd,dim);

    fclose(file);
    free(nonce);
    free(username);
    free(message);
    return true;   
}

bool seeOnlineUsers(Server &srv, int sd, unsigned char* buffer) {

    int byte_index = 0;    
    int dim = sizeof(char) + sizeof(int);
    vector<users> users_logged_in = srv.serverConn->getUsersList();

    for(size_t i = 0; i < users_logged_in.size(); i++) {
        cout << "utente " << users_logged_in[i].username << endl;
        dim += users_logged_in[i].username.size();
        dim += sizeof(int);
    }

    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::ONLINE, sizeof(char));
    byte_index += sizeof(char);

    int list_size = users_logged_in.size();
    memcpy(&(message[byte_index]), &list_size, sizeof(int));
    byte_index += sizeof(int);


    for(size_t i = 0; i < users_logged_in.size(); i++) {

        int username_size = users_logged_in[i].username.size();

        memcpy(&(message[byte_index]), &username_size, sizeof(int));
        byte_index += sizeof(int);

        memcpy(&(message[byte_index]), users_logged_in[i].username.c_str(), users_logged_in[i].username.size());
        byte_index += users_logged_in[i].username.size();
    }   

    srv.serverConn->send_message(message,sd,dim);

    return true;   
}

bool requestToTalk(Server &srv, int sd, unsigned char* buffer) {

    int byte_index = 0;    
    char opCode;
    int username_to_talk_to_size = 0;
    int username_size = 0;
    vector<users> users_logged_in = srv.serverConn->getUsersList();

    memcpy(&opCode, &(buffer[byte_index]), sizeof(char));
    byte_index += sizeof(char);

    memcpy(&username_to_talk_to_size, &(buffer[byte_index]), sizeof(int));
    byte_index += sizeof(int);

    unsigned char* username_to_talk_to = (unsigned char*)malloc(username_to_talk_to_size);

    memcpy(username_to_talk_to, &(buffer[byte_index]), username_to_talk_to_size);
    byte_index += username_to_talk_to_size;

    memcpy(&username_size, &(buffer[byte_index]), sizeof(int));
    byte_index += sizeof(int);

    unsigned char* username = (unsigned char*)malloc(username_size);

    memcpy(username, &(buffer[byte_index]), username_size);
    byte_index += username_size;

    cout << "so ";
    for(int i = 0; i < username_size; i++){
        cout << username[i];
    }
    cout << " want to talk with ";
    for(int i = 0; i < username_to_talk_to_size; i++){
        cout << username_to_talk_to[i];
    }
    cout << endl;

    byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + username_size;
    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::FORWARD, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &username_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), username, username_size);
    byte_index += username_size;

    int user_to_talk_to_sd = 0;
    for(size_t i = 0; i < users_logged_in.size(); i++) {
        if(strncmp(users_logged_in[i].username.c_str(), reinterpret_cast<const char*>(username_to_talk_to), username_size) == 0) {
            srv.serverConn->send_message(message,users_logged_in[i].sd, dim);
            user_to_talk_to_sd = users_logged_in[i].sd;
        }
    }

    unsigned char* response = (unsigned char*)malloc(sizeof(char));

    int ret = srv.serverConn->receive_message(user_to_talk_to_sd, response);
    if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
        perror("Send Error");
        throw runtime_error("Send failed");
    }   

    srv.serverConn->send_message(response, sd, dim);

    free(username_to_talk_to);
    free(username);
    return true;       
}