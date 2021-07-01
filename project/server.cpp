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
    vector<unsigned char> messageReceived;
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

        server_connection->initSet();
        server_connection->selectActivity();

        if(server_connection->isFDSet(server_connection->master_fd)) {
            server_connection->acceptNewConnection();
            } else {
                cout << "else" << endl;
                for(unsigned int i = 0; i < constants::MAX_REQUEST_QUEUED; i++)  {  
                    int sd = server_connection->getClient(i);
                    if (server_connection->isFDSet(sd)) {

                        server_connection->read_msg(buffer);
                        cout << "Message: " << buffer << endl;

                        //Check if it was for closing , and also read the 
                        //incoming message                         
                        /*
                        receive(ctx.serverSocket, sd, messageReceived);
                        cout << "Message received length: " << messageReceived.size() << endl;
                        if (messageReceived.size() == 0)  {
                            // thread err(errorhandling, ref(ctx), sd, i);
                            err.join();
                        } else {
                            int operationCode = messageReceived[0] - '0';
                            if (operationCode < 0 || operationCode > 5) {
                                cout << "Operation code not valid." << endl;
                                break;
                            }     

                            cout << "Operation code: " << operationCode << endl;

                            if (operationCode == 0) {
                                // Login
                                cout << endl << "-------Authentication-------" << endl;
                                thread auth(authentication,std::ref(ctx), sd, messageReceived);
                                auth.join();
                                cout << "-----------------------------" << endl;
                            } else if (operationCode == 1) {
                                cout << endl << "-------Close connection--------" << endl;
                                thread log(logout, std::ref(ctx), sd, i);
                                log.join();
                                cout << "------------------------------" << endl;
                            } else if (operationCode == 2) {
                                // Request to talk
                                cout << endl << "-------Request to Talk-------" << endl;
                                user = ctx.getUser(sd);
                                thread rtt(requestToTalk,std::ref(ctx), messageReceived, user);
                                rtt.join();
                                cout << "------------------------------" << endl;
                            } else if (operationCode == 3) {
                                //Message Forwarding
                                user = ctx.getUser(sd);
                                thread cht(chat, std::ref(ctx), messageReceived, user);
                                cht.join();
                            } else if (operationCode == 4) {
                                cout << endl << "----Online User List Request----" << endl;
                                user = ctx.getUser(sd);
                                cout << user.username << " requested the online users list" << endl;
                                thread onlusr(receiveOnlineUsersRequest, std::ref(ctx), user, messageReceived);
                                onlusr.join();
                                cout << "Online users list sent to " << user.username << endl;
                                cout << "---------------------------------" << endl;
                            } else if (operationCode == 5) {
                                cout << "\n----A client wants to close a chat----" << endl;
                                user = ctx.getUser(sd);
                                cout << user.username << " wants to close the chat" << endl;
                                chat(ctx, messageReceived, user);
                                thread log(logout, std::ref(ctx), sd, i);
                                log.join();
                                cout << "---------------------------------" << endl;
                            }
                        } */

                    }  
                    messageReceived.clear();
                }
        }

        return 0;
    }
}

