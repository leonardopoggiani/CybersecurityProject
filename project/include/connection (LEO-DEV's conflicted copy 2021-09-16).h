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
struct user {
    string username;
    int sd;
    unsigned char* session_key = NULL;

    user(string us, int s) {
        username = us;
        sd = s;
        session_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    }
};

struct userChat {
    unsigned char* username_1 = NULL;
    int dim_us1;
    int sd_1;
    unsigned char* username_2 = NULL;
    int dim_us2;
    int sd_2;
    EVP_PKEY* pubkey_1 = NULL;
    EVP_PKEY* pubkey_2 = NULL;
    unsigned char* iv = NULL;
    unsigned char* chat_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));

    userChat(unsigned char* us1, int d_us1, int s1, unsigned char* us2, int d_us2, int s2) {
        username_1 = (unsigned char*)malloc(d_us1);
        username_2 = (unsigned char*)malloc(d_us2);
        memcpy(username_1, us1, d_us1);
        memcpy(username_2, us2, d_us2);
        dim_us1 = d_us1;
        dim_us2 = d_us2;
        sd_1 = s1;
        sd_2 = s2;
    }

    userChat(unsigned char* us1, int d_us1, unsigned char* us2, int d_us2) {
        username_1 = (unsigned char*)malloc(d_us1);
        username_2 = (unsigned char*)malloc(d_us2);
        memcpy(username_1, us1, d_us1);
        memcpy(username_2, us2, d_us2);
        dim_us1 = d_us1;
        dim_us2 = d_us2;
    }
};

class clientConnection {

    protected:
        struct sockaddr_in address;
        int master_fd;
        int port;
        unsigned char* talking_to = NULL;
        unsigned char* iv = NULL;
        unsigned char* session_key = NULL;
        unsigned char* username = NULL;
        int username_size;
        userChat* current_chat = NULL;
        EVP_PKEY* keyDHBufferTemp = NULL;

    public:

        void setKeyDHBufferTemp(EVP_PKEY* keyDH, unsigned int size) {
            keyDHBufferTemp = keyDH;
        }

        EVP_PKEY* getKeyDHBufferTemp() {
            return keyDHBufferTemp;
        }

        unsigned char* getUsername() {
            return username;
        }

        int getUsernameSize() {
            return username_size;
        }
 
        void setUsername(string us) {
            username = (unsigned char*)malloc(us.size());
            username_size = us.size();
            memcpy(username, us.c_str(), us.size());
        }

        void setCurrentChat(unsigned char* username_to_contact, int us_size1, int sd1, unsigned char* username, int us_size2, int sd2) {
            current_chat = new userChat(username_to_contact, us_size1, sd1, username, us_size2, sd2);
        }

        void setCurrentChat(unsigned char* username_to_contact, int us_size1, unsigned char* username, int us_size2) {
            current_chat = new userChat(username_to_contact, us_size1, username, us_size2);
        }

        unsigned char* getSessionKey() {
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

        void generateIV(unsigned char* initialization_vector) {
            if(RAND_poll() != 1)
                throw runtime_error("An error occurred in RAND_poll."); 
            if(RAND_bytes(initialization_vector, constants::IV_LEN) != 1)
                throw runtime_error("An error occurred in RAND_bytes.");
        }

        clientConnection(){
            port = 8080;

            if ((master_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                cerr << RED << "\n[ERROR] Socket creation error \n" << RESET << endl;
                exit(1);
            } else {
                cout << "[LOG] socket created " << endl;
            }

            const int trueFlag = 1;
            setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));

            address.sin_family = AF_INET;
            address.sin_port = htons(constants::CLIENT_PORT);
            
            if(inet_pton(AF_INET, constants::LOCALHOST, &address.sin_addr) <= 0) {
                cerr << RED << "\n[ERROR] Address not supported \n" << RESET << endl;
                exit(1);
            } else {
                cout << "[LOG] address valid " << endl;
            }
        }

        int getMasterFD(){
            return master_fd;
        }

        ~clientConnection() {
            // Chiude il socket
            close(master_fd);
            cout << "[LOG] connection closed " << endl;
        }

        void make_connection(){
            bool is_blocking;
            int flags;
            int ret;
            flags = fcntl(master_fd, F_GETFL, 0);

            if(flags < 0) {
                cerr << RED << "[ERROR] connection error" << RESET << endl;
                exit(1);
            }

            if((flags & O_NONBLOCK) == 0) {
                is_blocking = true;
            } else {
                is_blocking = false;
            }

            ret = connect(master_fd, (struct sockaddr *)&address, sizeof(address));

            if (ret == -1) {
                if(is_blocking || errno != EINPROGRESS) { 
                    cerr << RED << "[ERROR] connection error" << RESET << endl;
                    exit(1);
                }

                if(!wait(master_fd)) {
                    cerr << RED << "[ERROR] connection error" << RESET << endl;
                    exit(1);
                }
            }
        }

        bool wait(int socket) {
            struct pollfd fds[1];
            int poll_response;

            if(socket < 0){
                cerr << RED << "[ERROR] socket descriptor not valid" << RESET << endl;
                exit(1);
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
                message_len = recv(sd, buffer, constants::MAX_MESSAGE_SIZE - 1, 0);
                
                if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    cerr << RED << "[ERROR] receive failed" << RESET << endl;
                    exit(1);
                } else if (message_len == 0) {
                    cout << "[LOG] client connection closed" << endl;
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
                    cerr << RED << "[ERROR] receive failed" << RESET << endl;
                    exit(1);
                } else if (message_len == 0) {
                    cout << "[LOG] client connection closed" << endl;
                    return 0;
                } 
            } while (message_len < 0);

            return message_len;
        }

        int send_message(string message) {
            int ret;

            if (message.length() > constants::MAX_MESSAGE_SIZE) {
                cerr << RED << "[ERROR] send failed" << RESET << endl;
                exit(1);
            }

            do {
                ret = send(getMasterFD(), message.c_str(), message.length(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    cerr << RED << "[ERROR] send failed" << RESET << endl;
                    exit(1);
                } else if (ret == 0) {
                    cout << "[LOG] client connection closed" << endl;
                    return -1;
                } 
            } while (ret != (int) message.length());
            return ret;
        }

        int send_message(vector<unsigned char> message) {
            int ret;

            if (message.size() > constants::MAX_MESSAGE_SIZE) {
                cerr << RED << "[ERROR] send failed" << RESET << endl;
                exit(1);
            }
            
            do {
                ret = send(getMasterFD(), &message[0], message.size(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    cerr << RED << "[ERROR] send failed" << RESET << endl;
                    exit(1);
                } else if (ret == 0) {
                    cout << "[LOG] client connection closed" << endl;
                    return 0;
                } 
            } while (ret != (int) message.size());

            return ret;
        }

        int send_message(unsigned char* message, int dim) {
            int ret = 0;
            
            do {
                ret = send(getMasterFD(), &message[0], dim, 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    cerr << RED << "[ERROR] send failed" << RESET << endl;
                    exit(1);
                } else if (ret == 0) {
                    cout << "[LOG] client connection closed" << endl;
                    return 0;
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

        void addSessionKey(unsigned char* sessionKey) {
            session_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
            memcpy(session_key, sessionKey, EVP_MD_size(EVP_sha256()));

            cout << "session_key: " << endl;
            BIO_dump_fp(stdout, (const char*)sessionKey, EVP_MD_size(EVP_sha256()));
        }

        userChat* getMyCurrentChat() {
            return current_chat;
        }
};

// #########################  SERVER ######################### //
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
        array<unsigned char, constants::IV_LEN> iv_server;

    public:

        unsigned char* getIV() {
            return iv_server.data();
        }

        void generateIV() {
            if(RAND_poll() != 1) {
                cerr << RED << "[ERROR] error in rand_poll" << RESET << endl;
                exit(1);
            }
            if(RAND_bytes(iv_server.data(), constants::IV_LEN) != 1) {
                cerr << RED << "[ERROR] error in rand_bytes" << RESET << endl;
                exit(1);
            }
        }

        void generateIV(unsigned char* initialization_vector) {
            if(RAND_poll() != 1) {
                cerr << RED << "[ERROR] error in rand_poll" << RESET << endl;
                exit(1);
            }
            if(RAND_bytes(initialization_vector, constants::IV_LEN) != 1) {
                cerr << RED << "[ERROR] error in rand_bytes" << RESET << endl;
                exit(1);
            }
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
            if (::bind(master_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
                cerr << RED << "[ERROR] error in binding" << RESET << endl;
                exit(1);  
            }
            cout << " [LOG] Listening on port: " <<  port << endl;  
        }

        void listenForConnections() {
            if (listen(master_fd, 3) < 0) {
                cerr << RED << "[ERROR] error in listening" << RESET << endl;
                exit(1);
            }
        }

        ~serverConnection() {
            close(master_fd);
            cout << "[LOG] connection closed " << endl;
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
            if (i > constants::MAX_CLIENTS - 1) {
                cerr << RED << "[ERROR] max clients exceeds" << RESET << endl;
                exit(1);
            }
            return client_socket[i];
        }

        void selectActivity() {
            activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
            if ((activity < 0) && (errno!=EINTR)) {
                cerr << RED << "[ERROR] error in select" << RESET << endl;
                exit(1);
            }
        }

        void accept_connection() {
            int new_socket;
            string message;

            try {
                if ((new_socket = accept(master_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
                    cerr << RED << "[ERROR] error in accept" << RESET << endl;
                    exit(1);
                }  

                cout << "********************************" << endl;
                cout << "New client online" << endl;
                cout << "Socket fd is \t" << new_socket << endl;
                cout << "IP: \t\t" <<  inet_ntoa(address.sin_addr) << endl;
                cout << "Port: \t\t" << ntohs(address.sin_port) << endl;
                cout << "********************************" << endl << endl;

                string buffer = "ack";

                if(send(new_socket, buffer.c_str(), buffer.size(), 0) != (ssize_t) buffer.size()) {
                    cerr << RED << "[ERROR] error in sending ack" << RESET << endl;
                    exit(1);
                }

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
                user* new_user = new user(username, sd);
                users_logged_in.push_back(*new_user);
            } else {
                cerr << RED << "[ERROR] error maximum number of client online" << RESET << endl;
                exit(1);
            }
        }

        void removeUser(int sd) {
            for(int i = 0; i < (int) users_logged_in.size(); i++) {
                if(users_logged_in[i].sd == sd) {
                    users_logged_in.erase(users_logged_in.begin() + i);
                    cout << "[LOG] removed user" << endl;
                    return;
                }
            }
            cout << "[LOG] no user found" << endl;
        }

        void printOnlineUsers(){
            if( users_logged_in.size() == 0 ) {
                cout << "[LOG] no users online" << endl;
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
                cerr << RED << "[ERROR] max message size exceeds" << RESET << endl;
                exit(1);
            }
            
            do {
                ret = send(sd, &message[0], message.size(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    cerr << RED << "[ERROR] send failed" << RESET << endl;
                    exit(1);
                } else if (ret == 0) {
                    cout << "[LOG] client connection closed" << endl;
                    return 0;
                }  
            } while (ret != (int) message.size());

            return ret;
        }

        int send_message(string message, int sd) {
            int ret;

            if (message.length() > constants::MAX_MESSAGE_SIZE) {
                cerr << RED << "[ERROR] max message size exceeds" << RESET << endl;
                exit(1);
            }

            do {
                ret = send(sd, message.c_str(), message.length(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    cerr << RED << "[ERROR] send failed" << RESET << endl;
                    exit(1);
                } else if (ret == 0) {
                    cout << "[LOG] client connection closed" << endl;
                    return 0;
                } 
            } while (ret != (int) message.length());

            return ret;
        }

        int send_message(unsigned char* message, int sd, int dim) {
            int ret;
            
            do {
                ret = send(sd, &message[0], dim, 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    cerr << RED << "[ERROR] send failed" << RESET << endl;
                    exit(1);    
                }  else if (ret == 0) {
                    cout << "[LOG] client connection closed" << endl;
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
            for(auto user : users_logged_in) {
                if(user.sd == sd) {
                    return user.session_key;
                }
            }
            
            return NULL;
        }

        void addSessionKey(int sd, unsigned char* sessionKey) {
            for(auto user : users_logged_in) {
                if(user.sd == sd) {
                    memcpy(user.session_key, sessionKey, EVP_MD_size(EVP_sha256()));
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

        userChat* getCurrentChat(int sd_to_search) {
            for(userChat* u : activeChat) {
                if(u->sd_1 == sd_to_search || u->sd_2 == sd_to_search) {
                    return u;
                }
            }
            return NULL;
        }
};


