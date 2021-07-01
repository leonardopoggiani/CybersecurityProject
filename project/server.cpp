#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "include/server.h"

using namespace std;

int main(int argc, char* const argv[]) {

    unsigned int counter = 0;
    int server_fd, new_socket, valread;
    struct sockaddr_in server_address, client_address;
    int opt = 1;
    int addrlen = sizeof(server_address);
    char buffer[constants::MAX_MESSAGE_SIZE] = {0};
    int len = sizeof(client_address);

    string hello = "hello from server";

    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        cerr << "Socket failed" << endl;
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(constants::PORT);

    if(bind(server_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        cerr << "Bind failed" << endl;
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, constants::MAX_REQUEST_QUEUED) < 0) {
        cerr << "Listen..." << endl;
        exit(EXIT_FAILURE);
    }

    while(1) {

        cout << "Sto aspettando nuove connessioni.." << endl;

        if ((new_socket = accept(server_fd, (struct sockaddr *)&server_address, (socklen_t*)&addrlen)) < 0) {
            cerr << "Accept..." << endl;
            exit(EXIT_FAILURE);
        }

        valread = read(new_socket , buffer, 1024);
        printf("%s\n",buffer );
        send(new_socket , hello.c_str() , hello.length() , 0);
        printf("Hello message sent\n");
    }

    return 0;
}

