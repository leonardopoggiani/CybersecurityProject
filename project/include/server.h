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

bool authentication(Server &srv, int sd) {
    vector<unsigned char> buffer;
    vector<unsigned char> signature;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    array<unsigned char, NONCE_SIZE> nonceServer;
    array<unsigned char, NONCE_SIZE> nonceClient;
    unsigned int tempBufferLen;
    string username;
    EVP_PKEY *pubKeyClient = NULL;
    EVP_PKEY *prvKeyServer = NULL;
    X509 *cert;

    //srv.crypto->generateNonce(nonceServer.data());


    // Extract username
   
    // Extract nc
    
    // Add certificate buffer to message

    //srv.crypto->readPrivateKey(prvKeyServer);

            
    /*srv.crypto->loadCertificate(cert, "ChatAppServer_cert");
    tempBufferLen = srv.crypto->serializeCertificate(cert, buffer.data());
    srv.serverConn->send_message(buffer);*/
    
    

    //ctx.crypto->getPublicKeyFromCertificate(cert, pubKeyServer);
    
    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    std::cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
    free(tmp);
    free(tmp2);

    return true;

    
}
