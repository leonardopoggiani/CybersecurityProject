#ifndef CONSTANTS_H
#define CONSTANTS_H
namespace constants
{
    constexpr unsigned int PORT = 8080;
    constexpr const char* LOCALHOST = "127.0.0.1";
    constexpr unsigned int NONCE_SIZE = 16;
    constexpr unsigned int TAG_LEN = 16;
    constexpr unsigned int IV_LEN = 12;
    constexpr unsigned int MAX_MESSAGE_SIZE = 10000;
    constexpr unsigned int MAX_REQUEST_QUEUED = 10;
    constexpr const char* CA_CERT_PATH = "ca_cert";
}
#endif