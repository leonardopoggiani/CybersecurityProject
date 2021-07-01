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
#include "include/costants.h"

using namespace std;

int main(int argc, char* const argv[]) {

    int ret;
    unsigned char* buffer = new unsigned char();
    serverConnection *server_connection = new serverConnection();
    ret = server_connection->connection();

    if( ret != 0 ){
        cerr << "--- connection failed ---" << endl;
        exit(EXIT_FAILURE);
    } else {
        cout << "--- connection done ---" << endl;
    }

    while(1) {

        cout << "--- waiting for connections ---" << endl;

        server_connection->accept_connection();

        ret = server_connection->read_msg(buffer);

        if( ret < 0 ) {
            cerr << "Error during read" << endl;
            exit(EXIT_FAILURE);
        } else if( ret == 0 ) {
            cout << "--- connection closed ---" << endl;
        }

        cout << "Message: " << buffer << endl;
    }

    return 0;
}

