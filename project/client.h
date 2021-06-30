#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <openssl/bio.h>
#include "crypto.h"

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

    void addNewUser(std::string username) {
        for(std::string onlineUser : userList) {
            if(username.compare(onlineUser) == 0) {
                return;
            }
        }
        userList.push_back(username);
    }

    void clearUserList() {
        userList.clear();
    }

    bool isUserOnline(std::string username){
        for(std::string user : userList){
            if(user.compare(username) == 0){
                return true;
            }
        }
        return false;
    }

};