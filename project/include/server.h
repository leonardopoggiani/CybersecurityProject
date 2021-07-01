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
    vector<OnlineUser> onlineUsers;
    vector<ActiveChat> activeChats;

    int client_socket[constants::MAX_CLIENTS];
    fd_set readfds;
    int max_sd;
    int sd;
    int activity;
    int addrlen;
    int port;
    char buffer[1025];

    int server_socket, new_socket, valread;
    struct sockaddr_in server_address;
    int opt = 1;
    int len = sizeof(server_address);

    public:

        serverConnection():clientConnection() {
            for (size_t i = 0; i < constants::MAX_CLIENTS; i++) {
                client_socket[i] = 0;
            }

            server_address.sin_addr.s_addr = INADDR_ANY;
            serverBind();
            listenForConnections();

        }

        void serverBind() {
            if (bind(master_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) 
                throw runtime_error("Error in binding");  
            cout << "Listening on port: " <<  port << endl;  
        }

        void listenForConnections() {
            if (listen(master_fd, 3) < 0)
                throw runtime_error("Error in listening");
        }

        ~serverConnection() {
            // Chiude il socket
            close(server_socket);
            cout << "--- connection closed ---" << endl;
        }

        int connection(){
            if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
                cerr << "Socket failed" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- socket created ---" << endl;
            }

            if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
                cerr << "Error in setting socket options" << endl;
                return -1;
            } else {
                cout << "--- socket configured ---" << endl;
            }

            server_address.sin_family = AF_INET;
            server_address.sin_addr.s_addr = INADDR_ANY;
            server_address.sin_port = htons(constants::SERVER_PORT);

            if(bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
                cerr << "Bind failed" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- bind succeded ---" << endl;
            }

            if (listen(server_socket, 3) < 0) {
                cerr << "Listen..." << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- listening ---" << endl;
            }

            return 0;
        }

        void accept_connection() {
            if ((new_socket = accept(server_socket, (struct sockaddr *)&server_address, (socklen_t*)&len)) < 0) {
                cerr << "Accept..." << endl;
                exit(EXIT_FAILURE);
            }
        }

        int send_msg(string msg) {
            // Invia la risposta
            if (send(new_socket, msg.c_str(), msg.length(), 0) < (int) msg.length()) {
                cerr << "Sent fewer bytes than expected" << endl;
                return -1;
            }
            return 0;
        };

        int send_msg(unsigned char const *msg, unsigned int size) {
            // Invia il messaggio
            if (send(new_socket, msg, size, 0) < size) {
                cerr << "\nSent fewer bytes than expected \n"
                    << endl;
                return -1;
            }
            return 0;
        };

        int read_msg(unsigned char *buffer) {
            int message_len;

            do {
                message_len = recv(sd, buffer, constants::MAX_MESSAGE_SIZE-1, 0);

                if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Receive Error");
                    throw runtime_error("Receive failed");
                }  
            } while (message_len < 0);
            
            buffer[message_len] = '\0';
            return message_len;   
        };

        void deleteUser(OnlineUser user) {
            bool found = false;
            unsigned int i = 0;

            for (OnlineUser usr : onlineUsers) {
                if (usr.username.compare(user.username) == 0){
                    found = true;
                    break;
                }
                i++;
            }

            if (found && i < onlineUsers.size()) {
                onlineUsers.erase(onlineUsers.begin() + i);
                return;
            }

            throw runtime_error("User not found");
        }

        void deleteActiveChat(OnlineUser user) {
            unsigned int i = 0;
            bool found = false;
            for (ActiveChat chat : activeChats) {
                if(chat.a.username.compare(user.username) == 0 || (chat.b.username.compare(user.username) == 0)) {
                    found = true;
                    break;
                }
                i++;
            }

            if (found && (i < activeChats.size())) {
                activeChats.erase(activeChats.begin() + i);
                return;
            }

            throw runtime_error("User was not chatting");
        }

        bool isUserChatting(string username){
            for(ActiveChat chat: activeChats) {
                if(chat.a.username.compare(username) == 0 || chat.b.username.compare(username) == 0){
                    return true;
                }
            }
            return false;
        }

        bool isUserOnline(string username){
            for(OnlineUser u : onlineUsers){
                if(u.username.compare(username) == 0){
                    return true;
                }
            }
            return false;
        }

        OnlineUser getUser(string username){
            for (OnlineUser user : onlineUsers) {
                if(username.compare(user.username) == 0) {
                    return user;
                }
            }
            throw runtime_error("User not authenticated");
        }

        OnlineUser getUser(int sd){
            for (OnlineUser user : onlineUsers) {
                if(user.sd == sd) {
                    return user;
                }
            }
            throw runtime_error("User not authenticated");
        }

        OnlineUser getReceiver(OnlineUser sender) {
            OnlineUser receiver;
            for (ActiveChat chat : activeChats) {
                if(chat.a.username.compare(sender.username) == 0) {
                    receiver = chat.b;
                    return receiver;
                }
                if (chat.b.username.compare(sender.username) == 0) {
                    receiver = chat.a;
                    return receiver;
                }
            }

            throw runtime_error("Receiver not found.");
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

            addrlen = sizeof(server_address);
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
            cout << "entrato" << endl;
            activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
            cout << "attivitá selezionata" << endl;
            if ((activity < 0) && (errno!=EINTR))
                throw runtime_error("Error in the select function"); 
        }

        void acceptNewConnection() {
            int new_socket;
            string message;

            try {
                if ((new_socket = accept(master_fd, 
                    (struct sockaddr *)&server_address, (socklen_t*)&addrlen))<0) {
                    perror("accept");  
                    throw runtime_error("Failure on accept");
                }  

                cout << "--------------------------------" << endl;
                cout << "New connection incoming" << endl;
                cout << "Socket fd is \t" << new_socket << endl;
                cout << "IP: \t\t" <<  inet_ntoa(server_address.sin_addr) << endl;
                cout << "Port: \t\t" << ntohs(server_address.sin_port) << endl;
                cout << "--------------------------------" << endl << endl;
                
                message = "Hi, i'm the server";
                if(send(new_socket, message.c_str(), message.length(), 0) != (ssize_t)message.length())  
                    throw runtime_error("Error sending the greeting message"); 

                for (unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  
                    if(client_socket[i] == 0)  {  
                        client_socket[i] = new_socket;  
                        break;  
                    } 
                }  
            } catch(const exception& e) {
                throw;
            }
        } 

        void readMessageOnOtherSockets() {
            int sd;
            int valread;
            
            for (unsigned int i = 0; i < constants::MAX_CLIENTS; i++)  {  
                sd = client_socket[i]; 
                if (FD_ISSET( sd , &readfds)) {  
                    valread = read(sd, buffer, 1024);    
                    if (valread == 0)  { 
                        disconnectHost(sd, i);
                    } else {  
                        buffer[valread] = '\0';  
                        send(sd , buffer , strlen(buffer) , 0 );
                    }  
                }  
            }  
        }

        void disconnectHost(int sd, unsigned int i) {
            getpeername(sd , (struct sockaddr*)&server_address , (socklen_t*)&addrlen);

            cout << "\n----Host disconnected----" << endl;
            cout << "IP: \t\t" << inet_ntoa(server_address.sin_addr) << endl;
            cout << "Port: \t\t" << ntohs(server_address.sin_port) << endl;
            cout << "-------------------------" << endl << endl;

            close(sd);  
            client_socket[i] = 0;
        }

};