#include <limits>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>

#include "costants.h"

using namespace std;


class serverConnection {
    int server_socket, new_socket, valread;
    struct sockaddr_in server_address;
    int opt = 1;
    int len = sizeof(server_address);

    ~serverConnection() {
        // Chiude il socket
        close(server_socket);
        cout << "--- connection closed ---" << endl;
    }

    public:
        int connection(){
            if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
                cerr << "Socket failed" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- socket created ---" << endl;
            }

            if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                        &opt, sizeof(opt))) {
                cerr << "Error in setting socket options" << endl;
                return -1;
            } else {
                cout << "--- socket configured ---" << endl;
            }

            server_address.sin_family = AF_INET;
            server_address.sin_addr.s_addr = INADDR_ANY;
            server_address.sin_port = htons(constants::PORT);

            if(bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
                cerr << "Bind failed" << endl;
                exit(EXIT_FAILURE);
            } else {
                cout << "--- bind succeded ---" << endl;
            }

            if (listen(server_socket, constants::MAX_REQUEST_QUEUED) < 0) {
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
            // Copia il messaggio nel buffer, aggiunge il carattere
            // di fine stringa e ritorna il numero di
            // byte letti (carattere di fine stringa escluso)
            int bytes_read = read(new_socket, buffer, constants::MAX_MESSAGE_SIZE);
            if (bytes_read < 0) {
                cerr << "Error in message reading" << endl;
                return -1;
            }
            // Manca il carattere di fine stringa
            buffer[bytes_read] = '\0';
            return bytes_read;
        };

};