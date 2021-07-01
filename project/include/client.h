#include <limits>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include "costants.h"

using namespace std;

class clientConnection {
    int client_socket, valread;
    struct sockaddr_in client_address;

    ~clientConnection() {
        // Chiude il socket
        close(client_socket);
        cout << "--- connection closed ---" << endl;
    }

    public:
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

            if (connect(client_socket, (struct sockaddr *)&client_address, sizeof(client_address)) < 0) {
                cerr << "\nConnection Failed \n" << endl;
                return -1;
            } else {
                cout << "--- socket connected ---" << endl;
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

        void seeOnlineUsers() {
            send_msg("hi");
        }

        void sendRequestToTalk(string username) {

        }
        
        void logout(){

        }

};