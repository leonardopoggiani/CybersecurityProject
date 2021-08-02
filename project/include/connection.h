#include <iostream>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <array>
#include <openssl/rand.h>
#include <vector>
#include <netinet/in.h>
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <errno.h>
#include "constants.h"
#include "color.h"

using namespace std;
class clientConnection {

    protected:
        struct sockaddr_in address;
        int master_fd;
        int port;
        unsigned char* talking_to;
        unsigned char* iv;
        unsigned char* session_key;
        


    public:

        unsigned char* getSessionKey() {
            printf("2) session key is:\n");
            BIO_dump_fp(stdout, (const char*)session_key, sizeof(session_key));

            return session_key;
        }

        unsigned char* getIV() {
            return iv;
        }

        void generateIV() {
            iv = (unsigned char*)malloc(constants::IV_LEN);

            if(RAND_poll() != 1)
                throw runtime_error("An error occurred in RAND_poll."); 
            if(RAND_bytes(iv, constants::IV_LEN) != 1)
                throw runtime_error("An error occurred in RAND_bytes.");
        }

        clientConnection(){
            port = 8080;
            if ((master_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                cerr << "\n Socket creation error \n" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- socket created ---" << endl;
            }

            const int trueFlag = 1;
            setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));

            address.sin_family = AF_INET;
            address.sin_port = htons(constants::CLIENT_PORT);
            
            if(inet_pton(AF_INET, constants::LOCALHOST, &address.sin_addr)<=0) {
                cerr << "\nInvalid address/ Address not supported \n" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- address valid ---" << endl;
            }
        }

        int getMasterFD(){
            return master_fd;
        }

        ~clientConnection() {
            // Chiude il socket
            close(master_fd);
            cout << "--- connection closed ---" << endl;
        }

        void make_connection(){
            bool is_blocking;
            int flags;
            int ret;
            flags = fcntl(master_fd, F_GETFL, 0);

            if(flags < 0) {
                perror("Connection error");
                throw runtime_error("Connection Failed");
            }

            if((flags & O_NONBLOCK) == 0) {
                is_blocking = true;
            } else {
                is_blocking = false;
            }

            ret = connect(master_fd, (struct sockaddr *)&address, sizeof(address));

            if (ret == -1) {
                if(is_blocking || errno != EINPROGRESS) { 
                    perror("Connection error");
                    throw runtime_error("Connection Failed");
                }

                if(!wait(master_fd)) {
                    perror("Connection Error");
                    throw runtime_error("Connection Failed");
                }
            }
        }

        bool wait(int socket) {
            struct pollfd fds[1];
            int poll_response;

            if(socket < 0){
                throw runtime_error("Socket descriptor not valid.");
            }

            fds[0].fd = socket;
            fds[0].events = POLLIN;

            poll_response = poll(fds, sizeof(fds)/sizeof(struct pollfd), 50);

            if (poll_response <= 0) {
                return false;
            }

            return true;
        }

        int receive_message(int sd, char* buffer) {
            int message_len;

            do {
                message_len = recv(sd, buffer, constants::MAX_MESSAGE_SIZE-1, 0);
                
                if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Receive Error");
                    throw runtime_error("Receive failed");
                } else if (message_len == 0) {
                    cout << "client connection closed" << endl;
                    return 0;
                } 
            } while (message_len < 0);

            buffer[message_len] = '\0';
            return message_len;
        }

        int receive_message(int sd, unsigned char* buffer) {
            int message_len;

            do {
                message_len = recv(sd, buffer, constants::MAX_MESSAGE_SIZE-1, 0);
                
                if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Receive Error");
                    throw runtime_error("Receive failed");
                } else if (message_len == 0) {
                    cout << "client connection closed" << endl;
                    return 0;
                } 
            } while (message_len < 0);

            return message_len;
        }

        int send_message(string message) {
            int ret;

            if (message.length() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }

            do {
                ret = send(getMasterFD(), message.c_str(), message.length(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                } else if (ret == 0) {
                    cout << "client connection closed" << endl;
                    return -1;
                } 
            } while (ret != (int) message.length());
            return ret;
        }

        int send_message(vector<unsigned char> message) {
            int ret;

            if (message.size() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }
            
            do {
                ret = send(getMasterFD(), &message[0], message.size(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                } else if (ret == 0) {
                    cout << "client connection closed" << endl;
                    return -1;
                } 
            } while (ret != (int) message.size());

            return ret;
        }

        int send_message(unsigned char* message, int dim) {
            int ret = 0;
            
            do {
                ret = send(getMasterFD(), &message[0], dim, 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                } else if (ret == 0) {
                    cout << "client connection closed" << endl;
                    return -1;
                } 
            } while (ret != dim);

            return ret;
        }

        bool checkAck(char* buffer) {
            if(strcmp(buffer,"ack") == 0){
                return true;
            } else 
                return false;
        }

        void setTalkingTo(unsigned char* talkingTo) {
            talking_to = talking_to;
        }

        void addSessionKey(unsigned char* sessionKey, int size) {
            session_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
            memcpy(session_key, sessionKey, EVP_MD_size(EVP_sha256()));

            printf("session key sent is:\n");
            BIO_dump_fp(stdout, (const char*)sessionKey, EVP_MD_size(EVP_sha256()));
            printf("session key new is:\n");
            BIO_dump_fp(stdout, (const char*)session_key, EVP_MD_size(EVP_sha256()));
        }
};

// #########################  SERVER ######################### //
struct user {
    string username;
    int sd;
    unsigned char* session_key;

    user(string us, int s) {
        username = us;
        sd = s;
        session_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    }
};

struct userChat {
    unsigned char* username_1;
    int sd_1;
    unsigned char* username_2;
    int sd_2;

    userChat(unsigned char* us1, int s1, unsigned char* us2, int s2) {
        username_1 = us1;
        username_2 = us2;
        sd_1 = s1;
        sd_2 = s2;
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

        vector<user> users_logged_in;
        vector<userChat*> activeChat;

        unsigned char* iv;

    public:

        unsigned char* getIV() {
            return iv;
        }

        void generateIV() {
            iv = (unsigned char*)malloc(constants::IV_LEN);
            if(RAND_poll() != 1)
                throw runtime_error("An error occurred in RAND_poll."); 
            if(RAND_bytes(iv, constants::IV_LEN) != 1)
                throw runtime_error("An error occurred in RAND_bytes.");
        }

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
                user* new_user = new user(username,sd);
                users_logged_in.push_back(*new_user);
            } else  {
                cerr << "Maximum number of online users reached" << endl;
                return;
            }
        }

        void removeUser(int sd) {
            cout << " removing user " << endl;
            for(int i = 0; i < (int) users_logged_in.size(); i++) {
                if(users_logged_in[i].sd == sd) {
                    users_logged_in.erase(users_logged_in.begin() + i);
                    cout << "removed user" << endl;

                    return;
                }
            }
            cout << "no user found" << endl;
        }

        void printOnlineUsers(){
            if( users_logged_in.size() == 0 ) {
                cout << "no users online" << endl;
                return;
            }

            for(auto user : users_logged_in) {
                cout << user.username << " | ";
            }
            cout << endl;
        }

        int send_message(vector<unsigned char> message, int sd) {
            int ret;

            if (message.size() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }
            
            do {
                ret = send(sd, &message[0], message.size(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                } else if (ret == 0) {
                    cout << "client connection closed" << endl;
                    return -1;
                }  
            } while (ret != (int) message.size());

            return ret;
        }

        int send_message(string message, int sd) {
            int ret;

            if (message.length() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }

            do {
                ret = send(sd, message.c_str(), message.length(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                } else if (ret == 0) {
                    cout << "client connection closed" << endl;
                    return -1;
                } 
            } while (ret != (int) message.length());

            return ret;
        }

        int send_message(unsigned char* message, int sd, int dim) {
            int ret;
            
            do {
                ret = send(sd, &message[0], dim, 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                }  else if (ret == 0) {
                    cout << "client connection closed" << endl;
                    return -1;
                } 
            } while (ret != dim);

            return ret;

        }

        vector<user> getUsersList() {
            return users_logged_in;
        }

        vector<userChat*> getActiveChats() {
            return activeChat;
        }

        void insertChat(userChat* u) {
            activeChat.push_back(u);
        }

        int findSd(int sd_to_search) {
            for(userChat* c : activeChat) {
                if(c->sd_1 == sd_to_search) {
                    return c->sd_2;
                } else if(c->sd_2 == sd_to_search) {
                    return c->sd_1;
                }
            }

            return -1;
        }

        unsigned char* getSessionKey(int sd) {

            cout << "sd: " << sd << endl;

            for(auto user : users_logged_in) {
                if(user.sd == sd) {
                    cout << "user: " << user.username << endl;

                    printf("2) session key is:\n");
                    BIO_dump_fp(stdout, (const char*)user.session_key, EVP_MD_size(EVP_sha256()));

                    return user.session_key;
                }
            }
            
            return NULL;
        }

        void addSessionKey(int sd, unsigned char* sessionKey) {

            printf("1) session key is:\n");
            BIO_dump_fp(stdout, (const char*)sessionKey, EVP_MD_size(EVP_sha256()));

            for(auto user : users_logged_in) {
                if(user.sd == sd) {

                    cout << "user: " << user.username << endl;

                    memcpy(user.session_key, sessionKey, EVP_MD_size(EVP_sha256()));

                    printf("2) session key is:\n");
                    BIO_dump_fp(stdout, (const char*)user.session_key, EVP_MD_size(EVP_sha256()));
                }
            }
        }

        string findUserFromSd(int sd_to_search) {
            for(user c : users_logged_in) {
                if(c.sd == sd_to_search) {
                    return c.username;
                }
            }
            return NULL;
        }
};


