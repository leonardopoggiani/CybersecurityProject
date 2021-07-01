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

    int ret;
    serverConnection *server_connection = new serverConnection();
    ret = server_connection->connection();

    if( ret != 0 ){
        cerr << "--- connection failed ---" << endl;
        exit(EXIT_FAILURE);
    } else {
        cout << "--- connection done ---" << endl;
    }

    while(1) {

        cout << "Sto aspettando nuove connessioni.." << endl;

        server_connection->accept_connection();

    }

    return 0;
}

