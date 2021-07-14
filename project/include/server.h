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
    unsigned char* nonceServer_rec= (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* cert_buf= NULL;
    X509 *cert;
    EVP_PKEY* server_key;
    unsigned int pubKeyDHBufferLen;
    EVP_PKEY *prvKeyDHServer = NULL;
    EVP_PKEY *pubKeyDHClient = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    unsigned int sgnt_size=*(unsigned int*)buffer;
	sgnt_size+=sizeof(unsigned int);
    int byte_index = 0;    
    char opCode;
   
    unsigned char* username;
    unsigned char* signature;
    unsigned char* nonceClient = (unsigned char*)malloc(constants::NONCE_SIZE);

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

    memcpy(nonceClient, &buffer[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(signature_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    signature = (unsigned char*)malloc(signature_size);
    memcpy(signature, &buffer[byte_index], signature_size);
    byte_index += signature_size;

    std::stringstream filename_stream;
    std::stringstream username_string;

    for(int i = 0; i < username_size; i++) {
        filename_stream << username[i];
        username_string << username[i];
    }

    cout << endl;

    filename_stream << "_pubkey.pem";

    string filename = filename_stream.str();

    string filename_dir = "keys/public/" + filename;
        
    FILE* file;
    file = fopen(filename_dir.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");

    EVP_PKEY *pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubkey){
        fclose(file);
        throw runtime_error("An error occurred while reading the public key.");
    }

    int dim = sizeof(char) + sizeof(int) + username_size + constants::NONCE_SIZE; 
    unsigned char* clear_buf = (unsigned char*)malloc(dim);

    memcpy(clear_buf, &buffer[byte_index], dim);
    byte_index += sizeof(char);

    int sign_size = 0;
    memcpy(&sign_size, &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* sign = (unsigned char*)malloc(sign_size);
    memcpy(sign, &buffer[byte_index], sign_size);
    byte_index += sign_size;
 
    
    unsigned int verify = srv.crypto->digsign_verify(sign, sign_size, clear_buf, sizeof(int), pubkey);
    if(verify<0){cerr<<"establishSession: invalid signature!"; return false;}
    
    srv.serverConn->insertUser(username_string.str(), sd);
    srv.serverConn->printOnlineUsers();
                         
    //Send packet with certificate

    //retrieve server private key
	
	srv.crypto->readPrivateKey("srv", "cybersecurity", server_key);
	if(!server_key) {cerr<<"establishSession: server_key Error";exit(1);}
	fclose(file);

    srv.crypto->generateNonce(nonceServer.data());

    srv.crypto->loadCertificate(cert, "server_cert");

    int cert_size = i2d_X509(cert, &cert_buf);        
    if(cert_size< 0) { 
        throw runtime_error("An error occurred during the reading of the certificate."); 
    }

    srv.crypto->keyGeneration(prvKeyDHServer);
    pubKeyDHBufferLen = srv.crypto->serializePublicKey(prvKeyDHServer, pubKeyDHBuffer.data());

    byte_index = 0;    
    //dim = sizeof(char) + sizeof(int) + cert_size + 2*constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferLen;
    dim = sizeof(char) + sizeof(int) + cert_size + constants::NONCE_SIZE + constants::NONCE_SIZE;
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

    //Aggiungere nonce client

    memcpy(&(message[byte_index]), nonceClient, constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    //Aggiungere la firma su tutto

    unsigned char* message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    unsigned int signed_size = srv.crypto->digsign_sign(message, dim, message_signed, server_key);

    //Spostare nel prossimo messaggio

   /* memcpy(&(message[byte_index]), &pubKeyDHBufferLen, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), pubKeyDHBuffer.data(), pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;*/


    //Aggiungere la firma

    srv.serverConn->send_message(message,sd,dim);

    free(nonceClient);
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

    for(auto user : activeChat) {
        if(memcmp(user->username_1, username, username_size) == 0 || 
            memcmp(user->username_2, username, username_size) == 0) 
            {
                cout << "user already chatting.." << endl;
                free(username_to_talk_to);
                free(username);

                unsigned char* already_chatting = (unsigned char*)malloc(sizeof(char));
                already_chatting[0] = 'n';

                srv.serverConn->send_message(already_chatting, sd, sizeof(char));

                free(already_chatting);
                return true;
            }

        if(memcmp(user->username_1, username_to_talk_to, username_to_talk_to_size) == 0 || 
            memcmp(user->username_2, username_to_talk_to, username_to_talk_to_size) == 0) 
            {
                cout << "user already chatting.." << endl;
                free(username_to_talk_to);
                free(username);

                unsigned char* already_chatting = (unsigned char*)malloc(sizeof(char));
                already_chatting[0] = 'n';

                srv.serverConn->send_message(already_chatting, sd, sizeof(char));

                free(already_chatting);
                return true;
            }
    }

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

    unsigned char* response = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);

    int ret = srv.serverConn->receive_message(user_to_talk_to_sd, response);
    if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
        perror("Send Error");
        throw runtime_error("Send failed");
    } else if(ret == 0) {
        cout << "client disconnected" << endl;
        return false;
    }

    srv.serverConn->send_message(response, sd, dim);

    free(username_to_talk_to);
    free(username);
    free(response);
    return true;       
}

bool start_chat(Server srv, int sd, unsigned char* buffer) {
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
            sd_1 = user.sd;
        }

        if(memcmp(user.username.c_str(), username_2, username_2_size) == 0) {
            sd_2 = user.sd;
        }
    }

    chat *new_chat = new chat(username_1, sd_1, username_2, sd_2);
    activeChat.push_back(new_chat);

    byte_index = 0;

    int dim_m1 = username_2_size + sizeof(int);
    unsigned char* m1 = (unsigned char*)malloc(dim_m1);

    memcpy(&(m1[byte_index]), &username_2_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(m1[byte_index]), username_2, username_2_size);
    byte_index += username_2_size;

    srv.serverConn->send_message(m1, sd_1, dim_m1);

    byte_index = 0;

    int dim_m2 = username_2_size + sizeof(int);
    unsigned char* m2 = (unsigned char*) malloc(dim_m2);

    memcpy(&(m2[byte_index]), &username_1_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(m2[byte_index]), username_1, username_1_size);
    byte_index += username_1_size;

    srv.serverConn->send_message(m2, sd_2, dim_m2);

    return true;
}

bool chatting(Server srv, int sd, unsigned char* buffer) {

    unsigned char* message_received;
    int message_size = 0;
    int byte_index = 0;
    int sd_to_send = -1;
    char opCode;

    for(chat* c : activeChat) {
        if(c->sd_1 == sd) {
            sd_to_send = c->sd_2;
        } else if(c->sd_2 == sd) {
            sd_to_send = c->sd_1;
        } else 
            sd_to_send = -1;
    }

    if(sd_to_send == -1) {
        cout << "no chat found" << endl;
        return false;
    }

    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    message_received = (unsigned char*)malloc(message_size);
    memcpy(message_received, &buffer[byte_index], message_size);
    byte_index += message_size;

    srv.serverConn->send_message(buffer, sd_to_send, byte_index);

    free(message_received);
    return true;   
}

