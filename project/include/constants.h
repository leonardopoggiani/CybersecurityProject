#ifndef CONSTANTS_H
#define CONSTANTS_H
namespace constants
{
    constexpr unsigned int CLIENT_PORT = 8080;
    constexpr unsigned int SERVER_PORT = 8888;
    constexpr const char* LOCALHOST = "127.0.0.1";
    constexpr unsigned int NONCE_SIZE = 16;
    constexpr unsigned int TAG_LEN = 16;
    constexpr unsigned int IV_LEN = 12;
    constexpr unsigned int MAX_MESSAGE_SIZE = 10000;
    constexpr int MAX_CLIENTS = 10;
    constexpr const char* CA_CERT_PATH = "ca_cert";
    constexpr const char* CRL_PATH = "./certificates/FoundationsOfCybersecurity_crl.pem";

    constexpr char AUTH = '1';
    constexpr char ONLINE = '2';
    constexpr char REQUEST = '3';
    constexpr char CHAT = '4';
    constexpr char LOGOUT = '5';
    constexpr char FORWARD = '6';
    constexpr char START_CHAT = '7';

}
#endif