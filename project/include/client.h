#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <openssl/bio.h>
#include "crypto.h"
#include "constants.h"
#include "socket.h"
#include <cstring>
#include <termios.h>
#include <sys/select.h>
#include "utils.h"
#include <iostream>

using namespace std;

std::string readMessage();
int sendMessage(std::string message);
void seeOnlineUsers();
void logout();
void sendRequestToTalk(std::string username);


class Client {

    public:
    std::vector<std::string> userList;
    EVP_PKEY* privateKeyClient;
    std::string username;
    Crypto* cryptoOperation;
    Socket* clientSocket;

    
    Client() {
        //clientSocket = new SocketClient(SOCK_STREAM);
        cryptoOperation = new Crypto();
    }

    void addNewUser(std::string username);
    void clearUserList();
    bool isUserOnline(std::string username);


};

bool authentication(Client &clt) {
        X509 *cert;
        EVP_PKEY *pubKeyServer = NULL;
    
        // load the CA's certificate:
        cout<< "Fatto!";
        
        clt.cryptoOperation->loadCertificate(cert, "ChatAppServer_cert");
       
        if(!clt.cryptoOperation->verifyCertificate(cert)) {
            throw runtime_error("Certificate not valid.");
        }
        cout << "Server certificate verified" << endl;


        //ctx.crypto->getPublicKeyFromCertificate(cert, pubKeyServer);
        
        // print the successful verification to screen:
        char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        std::cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
        free(tmp);
        free(tmp2);

        return true;
    }