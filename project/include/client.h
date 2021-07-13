#include <iostream>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <array>
#include <vector>
#include <netinet/in.h>
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <errno.h>
#include <termios.h>
#include "constants.h"
#include "connection.h"
#include "crypto.h"

using namespace std;
using namespace constants;

class clientConnection {

    protected:
        struct sockaddr_in address;
        int master_fd;
        int port;
        unsigned char* talking_to;


    public:

        clientConnection(){
            port = 8080;
            if ((master_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                cerr << "\n Socket creation error \n" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- socket created ---" << endl;
            }

            // Specifico di riusare il socket
            const int trueFlag = 1;
            setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));

            address.sin_family = AF_INET;
            address.sin_port = htons(constants::CLIENT_PORT);
            
            // Convert IPv4 and IPv6 addresses from text to binary form
            if(inet_pton(AF_INET, constants::LOCALHOST, &address.sin_addr)<=0) {
                cerr << "\nInvalid address/ Address not supported \n" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- address valid ---" << endl;
            }
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

            if( (flags & O_NONBLOCK) == 0){
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

        void seeOnlineUsers(){
            cout << "Let me see online users" << endl;

            int byte_index = 0;    

            int dim = sizeof(char);
            unsigned char* message = (unsigned char*)malloc(dim);  

            memcpy(&(message[byte_index]), &constants::ONLINE, sizeof(char));
            byte_index += sizeof(char);

            send_message(message, dim);

            unsigned char* buffer = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);

            int ret = receive_message(getMasterFD(), buffer);
            if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                perror("Receive Error");
                throw runtime_error("Receive failed");
            } 

            byte_index = 0;    

            dim = sizeof(char) + sizeof(int);
            char opCode;
            int list_size = 0; 

            memcpy(&(opCode), &buffer[byte_index], sizeof(char));
            byte_index += sizeof(char);

            memcpy(&(list_size), &buffer[byte_index], sizeof(int));
            byte_index += sizeof(int);

            if(list_size == 0) {
                cout << "--- no user online ---" << endl;
            } else {
                cout << "--- online users ---" << endl;

                for(int i = 0; i < list_size; i++) {
                    int username_size = 0;
                    memcpy(&(username_size), &buffer[byte_index], sizeof(int));
                    byte_index += sizeof(int);

                    unsigned char* username = (unsigned char*)malloc(username_size);
                    memcpy(username, &buffer[byte_index], username_size);
                    byte_index += username_size;

                    for(int j = 0; j < username_size; j++){
                        cout << username[j];
                    }

                    cout << " | ";
                    free(username);
                }

                cout << endl;
            }

            free(message);
            free(buffer);
        }

        int receive_message(int sd, char* buffer) {
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
        }

        int receive_message(int sd, unsigned char* buffer) {
            int message_len;

            do {
                message_len = recv(sd, buffer, constants::MAX_MESSAGE_SIZE-1, 0);
                
                if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Receive Error");
                    throw runtime_error("Receive failed");
                }  
            } while (message_len < 0);

            return message_len;
        }


        void send_message(string message) {
            int ret;

            if (message.length() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }

            do {
                ret = send(getMasterFD(), message.c_str(), message.length(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                }   
            } while (ret != (int) message.length());
        }

        void send_message(vector<unsigned char> message) {
            int ret;

            if (message.size() > constants::MAX_MESSAGE_SIZE) {
                throw runtime_error("Max message size exceeded in Send");
            }
            
            do {
                ret = send(getMasterFD(), &message[0], message.size(), 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                }   
            } while (ret != (int) message.size());
        }

        void send_message(unsigned char* message, int dim) {
            int ret = 0;
            
            do {
                ret = send(getMasterFD(), &message[0], dim, 0);
                if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Send Error");
                    throw runtime_error("Send failed");
                }   
            } while (ret != dim);

        }

        void sendRequestToTalk(string username_to_contact, string username) {
            int byte_index = 0;    

            int dim = sizeof(char) + sizeof(int) + username_to_contact.size() + sizeof(int) + username.size();
            unsigned char* message = (unsigned char*)malloc(dim);  

            memcpy(&(message[byte_index]), &constants::REQUEST, sizeof(char));
            byte_index += sizeof(char);

            int username_to_contact_size = username_to_contact.size();
            memcpy(&(message[byte_index]), &username_to_contact_size, sizeof(int));
            byte_index += sizeof(int);

            memcpy(&(message[byte_index]), username_to_contact.c_str(), username_to_contact.size());
            byte_index += username_to_contact.size();

            int username_size = username.size();
            memcpy(&(message[byte_index]), &username_size, sizeof(int));
            byte_index += sizeof(int);

            memcpy(&(message[byte_index]), username.c_str(), username.size());
            byte_index += username.size();

            send_message(message, dim);

            unsigned char* response = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);  
            receive_message(getMasterFD(), response);

            if(response[0] == 'y'){
                cout << "request accepted, starting the chat" << endl;
                cout << "---------------------------------------" << endl;
                cout << "\n-------Chat-------" << endl;

                start_chat(username, username_to_contact);

                chat();

                cout << "------------------" << endl;
            } else {
                cout << "we're sorry :(" << endl;
            }
        }

        void start_chat(string username, string username_to_contact) {
            cout << "start chat " << endl;
            int dim = username.size() + username_to_contact.size() + sizeof(char) + sizeof(int) + sizeof(int);
            unsigned char* buffer = (unsigned char*)malloc(dim);
            int byte_index = 0;    

            memcpy(&(buffer[byte_index]), &constants::START_CHAT, sizeof(char));
            byte_index += sizeof(char);

            int username_1_size = username.size();
            memcpy(&(buffer[byte_index]), &username_1_size, sizeof(int));
            byte_index += sizeof(int);

            memcpy(&(buffer[byte_index]), username.c_str(), username.size());
            byte_index += username.size();

            int username_2_size = username_to_contact.size();
            memcpy(&(buffer[byte_index]), &username_2_size, sizeof(int));
            byte_index += sizeof(int);
            
            memcpy(&(buffer[byte_index]), username_to_contact.c_str(), username_to_contact.size());
            byte_index += username_to_contact.size();

            cout << " ---- initializing chat ----" << endl;

            send_message(buffer,dim);
        }
        
        void logout() {
            cout << "logout" << endl;
            int byte_index = 0;    

            int dim = sizeof(char);
            unsigned char* message = (unsigned char*)malloc(dim);  

            memcpy(&(message[byte_index]), &constants::LOGOUT, sizeof(char));
            byte_index += sizeof(char);
            send_message(message, dim);
        }

        int getMasterFD(){
            return master_fd;
        }

        ~clientConnection() {
            // Chiude il socket
            close(master_fd);
            cout << "--- connection closed ---" << endl;
        }

        bool checkAck(char* buffer) {
            if(strcmp(buffer,"ack") == 0){
                return true;
            } else 
                return false;
        }

        void chat() {
            fd_set fds;
            string message;
            unsigned char* buffer = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
            unsigned char* to_send;
            int maxfd;

            int ret = receive_message(getMasterFD(), buffer);
            if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                perror("Send Error");
                throw runtime_error("Send failed");
            }   

            int username_size = 0;
            int byte_index = 0;

            memcpy(&(username_size), &buffer[byte_index], sizeof(int));
            byte_index += sizeof(int);

            unsigned char* username_talking_to = (unsigned char*)malloc(username_size);
            if(!username_talking_to) {
                throw runtime_error("malloc failed");
            }

            memcpy(username_talking_to, &buffer[byte_index], username_size);
            byte_index += username_size;

            cout << "Talking to ";

            for(int i = 0; i < username_size; i++) {
                cout << username_talking_to[i];
            }

            talking_to = username_talking_to; 

            cout << endl;

            buffer = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);

            while(1) {
                memset(buffer,0,constants::MAX_MESSAGE_SIZE);

                maxfd = (getMasterFD() > STDIN_FILENO) ? getMasterFD() : STDIN_FILENO;
                FD_ZERO(&fds);
                FD_SET(getMasterFD(), &fds); 
                FD_SET(STDIN_FILENO, &fds); 
                
                select(maxfd+1, &fds, NULL, NULL, NULL); 

                if(FD_ISSET(0, &fds)) {  
                    getline(cin, message); 

                    int byte_index = 0;
                    int dim_send = sizeof(char) + sizeof(int) + message.size();
                    to_send = (unsigned char*)malloc(dim_send);

                    memcpy(&(to_send[byte_index]), &(constants::CHAT), sizeof(char));
                    byte_index += sizeof(char);

                    int message_size = message.size();
                    memcpy(&(to_send[byte_index]), &message_size , sizeof(int));
                    byte_index += sizeof(int);

                    memcpy(&(to_send[byte_index]), message.c_str(), message_size);
                    byte_index += message_size;

                    send_message(to_send, dim_send);

                    cout << "sending: ";
                    for(int i = sizeof(char) + sizeof(int); i < dim_send; i++) {
                        cout << to_send[i];
                    }
                    cout << endl;

                    cin.ignore();
                }

                if(FD_ISSET(getMasterFD(), &fds)) {
                    receive_message(getMasterFD(), buffer);

                    int message_size = 0;
                    int byte_index = sizeof(char);

                    unsigned char* message;

                    memcpy(&(message_size), &buffer[byte_index], sizeof(int));
                    byte_index += sizeof(int);

                    message = (unsigned char*)malloc(sizeof(char) + sizeof(int) + message_size);
                    
                    memcpy(message, &buffer[byte_index], message_size);
                    byte_index += message_size;

                    for(int i = 0; i < username_size; i++) {
                        cout << username_talking_to[i];
                    }
                    cout << ": ";
        
                    for(int i = 0; i < message_size; i++) {
                        cout << message[i];
                    }

                    cout << endl;
                }
            }
            
        }

};

struct Client {
    EVP_PKEY *prvKeyClient;
    clientConnection *clientConn;
    CryptoOperation *crypto;  
    string username;  

    Client() {
        clientConn = new clientConnection();
        crypto = new CryptoOperation();
    }

    ~Client() {
        delete clientConn;
        delete crypto;
    }
};

string readMessage() {
    std::string message;
    getline(cin, message);
    if (message.length() > constants::MAX_MESSAGE_SIZE) {
        cerr << "Error: the message must be loger than " << endl;
        exit(EXIT_FAILURE);
    }
    return message;
}

void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

string readPassword() {
    string password;
    cout << "Insert password -> ";
    setStdinEcho(false);
    cin >> password;
    cin.ignore();
    setStdinEcho(true);
    cout << endl;
    return password;
}

bool authentication(Client &clt, string username, string password) {
    X509 *cert;
    EVP_PKEY *pubKeyServer = NULL;
    EVP_PKEY* user_key;
    vector<unsigned char> buffer;
    vector<unsigned char> packet;
    unsigned char* nonceServer;
    string to_insert;
    array<unsigned char, NONCE_SIZE> nonceClient;
    clt.username = username;

    string filename = "./keys/private/" + username + "_prvkey.pem";
	
	FILE* file = fopen(filename.c_str(), "r");
	if(!file) {
        cerr << "User does not have a key file" << endl; 
        exit(1);
    }   

	user_key = PEM_read_PrivateKey(file, NULL, NULL, (void*)password.c_str());
	if(!user_key) {
        cerr << "user_key Error" << endl; 
        exit(1);
    }
	fclose(file);
    
    clt.crypto->generateNonce(nonceClient.data());

    unsigned int byte_index = 0;   
    unsigned int byte_index_sign = 0;  
    int username_size = username.size();

    int dim = sizeof(char) + sizeof(int) + username.size() + nonceClient.size();
    int dim_to_sign = sizeof(char) + username.size() + nonceClient.size();

    unsigned char* message_sent = (unsigned char*)malloc(dim);      

    memcpy(&(message_sent[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message_sent[byte_index]), &username_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message_sent[byte_index]), username.c_str(), username.size());
    byte_index += username.size();

    memcpy(&(message_sent[byte_index]), nonceClient.data(), nonceClient.size());
    byte_index += nonceClient.size();

    unsigned char* message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    unsigned int signed_size = clt.crypto->digsign_sign(message_sent, dim, message_signed, user_key);
   
    clt.clientConn->send_message(message_signed, signed_size);
    free(message_sent);

    //ricevere certificato
    unsigned char* message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    int ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), message_received);
    if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
        perror("Send Error");
        throw runtime_error("Send failed");
    }   

    byte_index = 0;    
    int size_cert = 0;
    char opcode;

    memcpy(&(opcode), &message_received[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(size_cert), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* certificato = (unsigned char*)malloc(size_cert);

    memcpy(certificato, &message_received[byte_index], size_cert);
    byte_index += size_cert;

    nonceServer = (unsigned char*)malloc(constants::NONCE_SIZE);

    memcpy(nonceServer, &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    free(message_received);

    cert = d2i_X509(NULL, (const unsigned char**)&certificato, size_cert);

    if(!clt.crypto->verifyCertificate(cert)) {
        throw runtime_error("Certificate not valid.");
    }
    cout << "Server certificate verified" << endl;  

    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    std::cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
    free(tmp);
    free(tmp2);

    clt.crypto->getPublicKeyFromCertificate(cert, pubKeyServer);

    free(nonceServer);
    return true;
}

bool receiveRequestToTalk(Client &clt, char* msg) {
    unsigned int tempBufferLen = 0;
    unsigned int keyBufferLen = 0;
    unsigned int keyBufferDHLen = 0;
    EVP_PKEY *keyDH = NULL;
    EVP_PKEY *peerKeyDH = NULL;
    EVP_PKEY *peerPubKey = NULL;
    string input;
    bool verify = false;

    int byte_index = 0;
    unsigned char* username;
    int username_size;
    unsigned char response = 'n';

    byte_index += sizeof(char);

    memcpy(&(username_size), &msg[byte_index], sizeof(int));
    byte_index += sizeof(int);

    if(username_size < 0 || username_size > constants::MAX_MESSAGE_SIZE) {
        throw runtime_error("Username size error");
    }

    username = (unsigned char*)malloc(username_size);
    if(username == NULL) {
        throw runtime_error("Malloc error");
    }

    memcpy(username, &msg[byte_index], username_size);
    byte_index += username_size;

    if(memcpy((void*)clt.username.c_str(), username, username_size) == 0) {
        cout << "You're trying to speak with yourself, insert a valid username" << endl;
        return false;
    }

    cout << "Do you want to talk with ";
    for(int i = 0; i < username_size; i++) {
        cout << username[i];
    }

    cout << "? (y/n)" << endl;

    cin >> response;
    cin.ignore();

    if(response == 'y') {
        cout << "ok so i'll start the chat" << endl;
    } else {
        cout << ":(" << endl;
    }

    int dim = sizeof(char);
    byte_index = 0;
    unsigned char* response_to_request = (unsigned char*)malloc(dim);  
    if(response_to_request == NULL) {
        throw runtime_error("Malloc error");
    }

    memcpy(response_to_request, &response, sizeof(char));
    byte_index += sizeof(char);

    clt.clientConn->send_message(response_to_request, dim);

    free(response_to_request);
    free(username);
    return true;
}
