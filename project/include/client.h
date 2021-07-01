#include <limits>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>    //close
#include <errno.h>
#include "costants.h"

using namespace std;

class clientConnection {
    int client_socket, valread;
    struct sockaddr_in client_address;

    public:
        int master_fd;

        int connection(){
            if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                cerr << "\n Socket creation error \n" << endl;
                return -1;
            } else {
                cout << "--- socket created ---" << endl;
            }

            client_address.sin_family = AF_INET;
            client_address.sin_port = htons(constants::PORT);
            
            // Convert IPv4 and IPv6 addresses from text to binary form
            if(inet_pton(AF_INET, constants::LOCALHOST, &client_address.sin_addr)<=0) {
                cerr << "\nInvalid address/ Address not supported \n" << endl;
                return -1;
            } else {
                cout << "--- address valid ---" << endl;
            }

            bool is_blocking;
            int flags;
            int ret;
            flags = fcntl(master_fd, F_GETFL, 0);

            if(flags < 0) {
                perror("Connection error");
                throw runtime_error("Connection Failed");
            }

            is_blocking = (flags & O_NONBLOCK) == 0;
            ret = connect(master_fd, (struct sockaddr *)&client_address, sizeof(client_address));

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

            return 0;
        }

        int send_msg(string msg) {
            // Invia il messaggio
            if (send(client_socket, msg.c_str(), msg.length(), 0) < (int) msg.length()) {
                cerr << "\nSent fewer bytes than expected \n"
                    << endl;
                return -1;
            }
            return 0;
        };

        int send_msg(unsigned char const *msg, unsigned int size) {
            // Invia il messaggio
            if (send(client_socket, msg, size, 0) < size) {
                cerr << "\nSent fewer bytes than expected \n"
                    << endl;
                return -1;
            }
            return 0;
        };

        int read_msg(unsigned char *buffer) {
            // Copia il messaggio nel buffer, aggiunge il carattere
            // di fine stringa e ritorna il numero di
            // byte letti (carattere di fine stringa escluso)
            int bytes_read = read(client_socket, buffer, constants::MAX_MESSAGE_SIZE);
            if (bytes_read < 0) {
                cerr << "\nError in message reading \n"
                    << endl;
                return -1;
            }
            // Manca il carattere di fine stringa
            buffer[bytes_read] = '\0';
            return bytes_read;
        };

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


        void seeOnlineUsers() {
            send_msg("hi");
        }

        void sendRequestToTalk(string username) {

        }
        
        void logout(){

        }

        ~clientConnection() {
            // Chiude il socket
            close(client_socket);
            cout << "--- connection closed ---" << endl;
        }

};