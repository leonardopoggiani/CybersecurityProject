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

using namespace std;

struct OnlineUser {
    string username;
    int sd;
    unsigned int key_pos;

    OnlineUser(){}

    OnlineUser(string usr, int _sd) {
        username = usr;
        sd = _sd;
        key_pos = _sd;
    }
};

struct ActiveChat {
    OnlineUser a;
    OnlineUser b;

    ActiveChat(OnlineUser an, OnlineUser bn){
        a = an;
        b = bn;
    }
};


class serverConnection : public clientConnection{
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

                cout << "--------------------------------" << endl;
                cout << "New connection incoming" << endl;
                cout << "Socket fd is \t" << new_socket << endl;
                cout << "IP: \t\t" <<  inet_ntoa(address.sin_addr) << endl;
                cout << "Port: \t\t" << ntohs(address.sin_port) << endl;
                cout << "--------------------------------" << endl << endl;
                
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


        void disconnectHost(int sd, unsigned int i) {
            getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);

            cout << "\n----Host disconnected----" << endl;
            cout << "IP: \t\t" << inet_ntoa(address.sin_addr) << endl;
            cout << "Port: \t\t" << ntohs(address.sin_port) << endl;
            cout << "-------------------------" << endl << endl;

            close(sd);  
            client_socket[i] = 0;
        }

        

};
