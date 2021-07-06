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
#include <arpa/inet.h>    //close
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <errno.h>
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
                
                message = "Hi, i'm the server";
                if(send(new_socket, message.c_str(), message.length(), 0) != (ssize_t)message.length())  
                    throw runtime_error("Error sending the greeting message"); 

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
    //vector<OnlineUser> onlineUsers;
    //vector<ActiveChat> activeChats;
    serverConnection *serverConn;
    CryptoOperation *crypto;

    Server() {
        serverConn = new serverConnection();
        crypto = new CryptoOperation();
    }
};

#define OPCODE_SIZE 1
#define PAYLOAD_LEN_SIZE sizeof(int)
#define COUNTER_SIZE sizeof(int)

typedef struct {
    char opcode;
    unsigned int payload_len;
    unsigned char* payload;
} Message;  

int add_header(unsigned char* buffer, char opcode, int payload_len, unsigned char* payload) {
    // initializing the index in the buffer
    int byte_index = 0;

    // creating header: opcode
    char* opcode_ptr = (char*)&buffer[byte_index];
    *opcode_ptr = opcode;
    byte_index += OPCODE_SIZE;

    // creating header: payload_len
    int* payload_len_ptr = (int*)&buffer[byte_index];
    *payload_len_ptr = payload_len;
    byte_index += PAYLOAD_LEN_SIZE;

    // adding the payload
    memcpy(&buffer[byte_index], payload, payload_len);
    byte_index += payload_len;

    return byte_index;
}

bool send_MESSAGE(int sock, Message* mex) {
    if (mex == NULL) return false;
    unsigned char* buffer_to_send = (unsigned char*)malloc(OPCODE_SIZE + PAYLOAD_LEN_SIZE + mex->payload_len);
    int byte_to_send = add_header(buffer_to_send, mex->opcode, mex->payload_len, mex->payload);
    int byte_correctly_sent = send(sock, buffer_to_send, byte_to_send, 0);
    BIO_dump_fp(stdout, (const char *)buffer_to_send, byte_to_send);
    free(buffer_to_send);
    return byte_correctly_sent == byte_to_send ? true : false;
}

bool read_MESSAGE(int sock, Message* mex_received) {
    read(sock, &mex_received->opcode, OPCODE_SIZE);
    // Retrieve remaining part of message (payload_len)
    read(sock, &mex_received->payload_len, PAYLOAD_LEN_SIZE);
    mex_received->payload = (unsigned char*)malloc(mex_received->payload_len);
    // Retrieve remaining part of message (payload)
    int read_byte = read(sock, mex_received->payload, mex_received->payload_len);
    return read_byte == mex_received->payload_len ? true : false;
}

bool read_MESSAGE_payload(int sock, Message* mex_received) {
    read(sock, &mex_received->payload_len, PAYLOAD_LEN_SIZE);
    mex_received->payload = (unsigned char*)malloc(mex_received->payload_len);
    // Retrieve remaining part of message (payload)
    int read_byte = read(sock, mex_received->payload, mex_received->payload_len);
    return read_byte == mex_received->payload_len ? true : false;
}

bool authentication(Server &srv, int sd, char* buffer) {
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

    char* opcode = strtok(buffer, "|");
    char* username = strtok(NULL, "|");
    char* password = strtok(NULL, "|");
    char* nonce = strtok(NULL, "|");

    // controllare che username password e nonce non abbiamo la barra nel mezzo, altrimenti sono problemi
    cout << "opcode: " << opcode << ",username: " << username << ",password: " << password << endl;

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

    packet.push_back('|');
    packet.push_back('1');
    packet.push_back('|');

    srv.crypto->generateNonce(nonceServer.data());

    for(int i = 0 ; i < nonceServer.size() ; i++) {
        packet.push_back(nonceServer[i]);
    }

    packet.push_back('|');

    srv.crypto->loadCertificate(cert, "ChatAppServer_cert");
    int cert_size = i2d_X509(cert, &cert_buf);        
    if(cert_size< 0) { throw runtime_error("An error occurred during the reading of the certificate."); }
    
    uint16_t lmsg = htons(cert_size);

    //Accodare certificato e dimensione in qualche modo e spedire packet

    // ret = send(sd, (void*) &lmsg, sizeof(uint16_t), 0);

    for(int i = 0; i < cert_size; i++) {
        packet.push_back(*(cert_buf+i));
    }

    // srv.serverConn->send_message(packet,sd);  
    cout << "inizio invio certificato" << endl;

    int byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + cert_size;
    cout << "dim: " << dim << endl;
    unsigned char* message = (unsigned char*)malloc(sizeof(char) + sizeof(int) + cert_size);  // POSTPONED AFTER EpubKa(..)

    memcpy(&(message[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &cert_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), &cert_buf[0], cert_size);
    byte_index += cert_size;

    srv.serverConn->send_message(message,sd,dim);

    return true;   
}
