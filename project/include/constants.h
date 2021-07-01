#ifndef CONSTANTS_H
#define CONSTANTS_H

using namespace std;

namespace constants
{
    constexpr unsigned int PORT = 8080;
    constexpr const char* LOCALHOST = "127.0.0.1";
    constexpr unsigned int NONCE_SIZE = 16;
    constexpr unsigned int MAX_MESSAGE_SIZE = 10000;
    constexpr unsigned int MAX_REQUEST_QUEUED = 10;
    //CERTIFICATE PATH
    const string CA_CERT_PATH = "ca_cert";
}
#endif