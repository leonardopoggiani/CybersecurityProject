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
#include "constants.h"
#include "connection.h"
#include "crypto.h"



using namespace std;
using namespace constants;


void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

class clientConnection {

    protected:
        struct sockaddr_in address;
        int master_fd;
        int port;

    public:

        clientConnection(){
            port = 8080;
            if ((master_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                cerr << "\n Socket creation error \n" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- socket created ---" << endl;
            }

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

        void seeOnlineUsers(vector<unsigned char> command_received){
            cout << "let me see online users" << endl;
            command_received.push_back(constants::ONLINE);

            send_message(command_received);
        }

        int receive_message(int sd, char* buffer) {
            int message_len;

            do {
                message_len = recv(sd, buffer, constants::MAX_MESSAGE_SIZE-1, 0);
                cout << "returned: " << message_len << endl;
                
                if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
                    perror("Receive Error");
                    throw runtime_error("Receive failed");
                }  
            } while (message_len < 0);

            buffer[message_len] = '\0';
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

            cout << "send riuscita: " << message.size() << endl;
        }

        void sendRequestToTalk(vector<unsigned char> command_received, string username) {
            cout << "let me talk to someone" << endl;

            
            command_received.push_back(constants::REQUEST);

            send_message(command_received);
        }
        
        void logout(vector<unsigned char> command_received) {
            cout << "let me see online users" << endl;
            command_received.push_back('|');
            command_received.push_back(constants::LOGOUT);
            command_received.push_back('|');
            send_message(command_received);
        }

        int getMasterFD(){
            return master_fd;
        }

        ~clientConnection() {
            // Chiude il socket
            close(master_fd);
            cout << "--- connection closed ---" << endl;
        }

};

string readMessage() {
    string message;
    getline(cin, message);
    if (message.length() > constants::MAX_MESSAGE_SIZE) {
        cerr << "Error: the message must be loger than " << endl;
        exit(EXIT_FAILURE);
    }
    return message;
}

struct Client {
    EVP_PKEY *prvKeyClient;
    clientConnection *clientConn;
    CryptoOperation *crypto;
    string username;
    string peerUsername;

    Client() {
        clientConn = new clientConnection();
        crypto = new CryptoOperation();
    }

   
};

string readPassword() {
    string password;
    cout << "Insert password: ";
    setStdinEcho(false);
    cin >> password;
    cin.ignore();
    setStdinEcho(true);
    cout << endl;
    return password;
}

bool authentication(Client &clt) {
    X509 *cert;
    EVP_PKEY *pubKeyServer = NULL;

    vector<unsigned char> buffer;
    vector<unsigned char> packet;
    vector<unsigned char> signature;
    string username;
    string password;
    string to_insert;
    int ret;
    array<unsigned char, NONCE_SIZE> nonceClient;
    array<unsigned char, NONCE_SIZE> nonceServer;
    //array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    char* bufferTemp;

    packet.push_back('|');
    packet.push_back('1');
    packet.push_back('|');
    cout << "Welcome! Please type your username" << endl;
    cin >> username;

    for(int i = 0 ; i < username.size() ; i++) {
        packet.push_back(username[i]);
    }
    packet.push_back('|');

    cout << "Fine! Now insert you password to chat with others" << endl;
    password = readPassword();
    for(int i = 0 ; i < password.size() ; i++) {
        packet.push_back(password[i]);
    }
    packet.push_back('|');
    
    cout << "to_insert: " << packet.data() << endl;  

    clt.crypto->generateNonce(nonceClient.data());
    for(int i = 0 ; i < nonceClient.size() ; i++) {
        packet.push_back(nonceClient[i]);
    }
    
    cout << "packet: " <<  packet.data() << endl;   

    clt.clientConn->send_message(packet);
    
    //ricevere certificato, da spostare in authentication
    u_int16_t lmsg;
    ret = recv(clt.clientConn->getMasterFD(), (void*)&lmsg, sizeof (uint16_t), 0);      

    if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
        perror("Receive Error");
        throw runtime_error("Receive failed");
    }  

    int cert_len = ntohs(lmsg);
    unsigned char* cert_buf = (unsigned char*) malloc(cert_len);
    recv(clt.clientConn->getMasterFD(), cert_buf, cert_len, MSG_WAITALL);
    cert = d2i_X509(NULL, (const unsigned char**)&cert_buf, cert_len);
    cout << "certificate received" << endl;

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

    return true;
}

