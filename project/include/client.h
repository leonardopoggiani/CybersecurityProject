#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <openssl/bio.h>
#include "crypto.h"
#include "costants.h"

std::string readMessage();
int sendMessage(std::string message);
void seeOnlineUsers();
void logout();
void sendRequestToTalk(std::string username);


class Client {
    std::vector<std::string> userList;
    EVP_PKEY* privateKeyClient;
    std::string username;
    Crypto* cryptoOperation;

    Client() {}

    void addNewUser(std::string username);
    void clearUserList();
    bool isUserOnline(std::string username);

};