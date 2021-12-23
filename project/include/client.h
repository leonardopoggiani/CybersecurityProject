#include <iostream>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <array>
#include <vector>
#include <netinet/in.h>
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <errno.h>
#include <termios.h>
#include "constants.h"
#include "crypto.h"
#include "color.h"

using namespace std;
using namespace constants;

struct Client {
    EVP_PKEY *prvKeyClient;
    clientConnection *clientConn = new clientConnection();
    CryptoOperation *crypto = new CryptoOperation();
};

string readMessage() {
    string message;
    getline(cin, message);
    if (message.length() > constants::MAX_MESSAGE_SIZE) {
        cerr << RED << "Error: the message must be loger than this" << RESET << endl;
        exit(EXIT_FAILURE);
    }
    return message;
}

void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

string readPassword() {
    string password;
    cout << "Insert password -> ";
    setStdinEcho(false);
    cin >> password;
    cin.ignore();
    setStdinEcho(true);
    cout << endl;
    return password;
}

void secureSum(int a, int b){
    if (a > INT_MAX - b){
        cout << RED << "[ERROR] integer overflow" << RESET << endl;
        exit(1);
    }
    
}

int send_message_enc(int masterFD, Client clt, unsigned char* message, int dim, vector<unsigned char> &encrypted, counterSession *s) {
    int ret = 0;

    unsigned char* session_key = clt.clientConn->getSessionKey();

    clt.clientConn->generateIV();
    unsigned char* iv = clt.clientConn->getIV();
    if(!iv) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    encrypted.resize(dim);
    int encrypted_size = clt.crypto->encryptMessage(session_key, iv, message, dim, encrypted, s);

    do {
        ret = send(masterFD, encrypted.data(), encrypted_size, 0);
        if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            cerr << RED << "[ERROR] send failed " << RESET << endl;
            exit(EXIT_FAILURE);
        } else if (ret == 0) {
            cout << "[ERROR] client connection closed" << endl;
            return 0;
        } 
    } while (ret != encrypted_size);

    return ret;
}

int receive_message_enc(Client clt, unsigned char* message, vector<unsigned char> &decrypted, counterSession *s) {
    int message_len = -1;

    do {
        message_len = recv(clt.clientConn->getMasterFD(), message, constants::MAX_MESSAGE_SIZE-1, 0);
        
        if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            cerr << RED << "[ERROR] receive failed " << RESET << endl;
            exit(EXIT_FAILURE);
        } else if (message_len == 0) {
            cout << "[ERROR] client connection closed" << endl;
            return 0;
        } 
    } while (message_len < 0);

    int decrypted_size = clt.crypto->decryptMessage(clt.clientConn->getSessionKey(), message, message_len, decrypted, s);

    return decrypted_size;
}

bool authentication(Client &clt, string username, string password) {
    X509 *cert;
    EVP_PKEY* user_key = NULL;
    EVP_PKEY *pubKeyServer = NULL;
    EVP_PKEY *pubKeyDHServer = NULL;
    EVP_PKEY *prvKeyDHClient = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBufferServer;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    array<unsigned char, NONCE_SIZE> nonceClient;
    array<unsigned char, NONCE_SIZE> nonceServer;
    array<unsigned char, NONCE_SIZE> nonceClient_rec;
    array<unsigned char, NONCE_SIZE> nonceClient_t;
    vector<unsigned char> buffer;
    
    unsigned char* signature = NULL;
    unsigned char* message_signed = NULL;
    int dim_to_sign;
    int signature_size;
    unsigned char* message_to_sign;
    string to_insert;
    unsigned int pubKeyDHBufferLen = 0;
    unsigned int pubKeyDHBufferServerLen = 0;



    string filename = "./keys/private/" + username + "_prvkey.pem";

    clt.clientConn->setUsernameS(username);
	
	FILE* file = fopen(filename.c_str(), "r");
	if(!file) {
        cerr << RED << "[ERROR] User does not have a key file" << RESET << endl; 
        exit(1);
    }   

	user_key = PEM_read_PrivateKey(file, NULL, NULL, (void*)password.c_str());
	if(!user_key) {
        cerr << RED << "[ERROR] Password not valid, retry" << RESET << endl; 
        return false;
    }

	fclose(file);

    clt.clientConn->setPassword(password);
    
    clt.crypto->generateNonce(nonceClient.data());

    // conservo il nonce per verificarlo al passo successivo
    memcpy(nonceClient_t.data(), nonceClient.data(), constants::NONCE_SIZE);

    int byte_index = 0;   

    

    secureSum(username.size(), sizeof(char) + sizeof(int));
    secureSum(username.size() + sizeof(int) + sizeof(char), nonceClient.size());

    dim_to_sign = username.size() + sizeof(char) + sizeof(int);

    message_to_sign = (unsigned char*)malloc(dim_to_sign);   
    if(!message_to_sign) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }   


    memcpy(&(message_to_sign[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    int username_size = username.size();
    memcpy(&(message_to_sign[byte_index]), &username_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message_to_sign[byte_index]), username.c_str(), username.size());
    byte_index += username.size();

    message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    if(!message_signed) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    unsigned int signed_size = clt.crypto->digsign_sign(message_to_sign, dim_to_sign, message_signed, user_key);
    if(signed_size < 0) {
        cerr << RED << "[ERROR] invalid signature!" << RESET << endl;
        return false;
    } else {
        cout << GREEN << "[LOG] valid signature " << RESET << endl;
    }

    byte_index = 0;

    int dim = signed_size + sizeof(int) + constants::NONCE_SIZE;

    unsigned char* message_sent = (unsigned char*)malloc(dim);   
    if(!message_sent) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }   

    const char* message_signed_t = reinterpret_cast<const char *>(message_signed);

    memcpy(&(message_sent[byte_index]), message_signed_t, signed_size + sizeof(int));
    byte_index += signed_size + sizeof(int);

    memcpy(&(message_sent[byte_index]), nonceClient.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;


    clt.clientConn->send_message(message_sent, byte_index);

    free(message_sent);
    free(message_signed);

    // ricevere certificato
    unsigned char* message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    if(!message_received) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }   

    int ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), message_received);
    if(ret == 0) {
        cout << RED << "[LOG] client connection closed " << RESET << endl;
        free(message_received);
        return false;
    }

    byte_index = 0;
    signed_size = 0;
    size_t size_cert = 0;

    //Cose firmate

    int clear_byte_index = byte_index;
    dim = sizeof(char) + constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferServerLen; 
    unsigned char* clear_buf = (unsigned char*)malloc(dim);
    if(!clear_buf) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(clear_buf, &message_received[clear_byte_index], dim);
    clear_byte_index += dim;

    byte_index += sizeof(char);

    memcpy(nonceClient_rec.data(), &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(pubKeyDHBufferServerLen), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    memcpy(pubKeyDHBufferServer.data(), &message_received[byte_index], pubKeyDHBufferServerLen);
    byte_index += pubKeyDHBufferServerLen;
    
    memcpy(&(signature_size), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);
    
    signature = (unsigned char*)malloc(signature_size);
    if(!signature) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    } 

    memcpy(signature, &message_received[byte_index], signature_size);
    byte_index += signature_size;
    
    memcpy(&size_cert, &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* cert_buf = (unsigned char*)malloc(size_cert);
    if(!cert_buf) {
        cerr << RED << "[ERROR] malloc error on certification buffer" << RESET << endl; 
        exit(1);
    }

    memcpy(cert_buf, &message_received[byte_index], size_cert);
    byte_index += size_cert;


    memcpy(nonceServer.data(), &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;


    cert = d2i_X509(NULL, (const unsigned char**)&cert_buf, size_cert);

    if(!clt.crypto->verifyCertificate(cert)) {
        cerr << RED << "[ERROR] error in certificate verification" << RESET << endl; 
        exit(1);
    }
    
    cout << GREEN << "[LOG] server certificate verified" << RESET << endl;  

    clt.crypto->getPublicKeyFromCertificate(cert, pubKeyServer);

    unsigned int verify = clt.crypto->digsign_verify(signature, signature_size, clear_buf, sizeof(int), pubKeyServer);
    if(verify < 0){
        cerr << RED << "[ERROR] invalid signature!" << endl;
        return false;
    } else { 
        cout << GREEN << "[LOG] valid Signature " << RESET << endl;
    }

    // Verificare nonce
    if(memcmp(nonceClient_t.data(), nonceClient_rec.data(), constants::NONCE_SIZE) != 0){
        cerr << RED << "[ERROR] nonce received is not valid!" << RESET << endl;
        exit(1);
    } else {
        cout << GREEN << "[LOG] nonce verified " << RESET << endl;
    }

    // -- SCAMBIO CHIAVE DI SESSIONE -- 

    clt.crypto->generateNonce(nonceClient.data());

    clt.crypto->keyGeneration(prvKeyDHClient);
    pubKeyDHBufferLen = clt.crypto->serializePublicKey(prvKeyDHClient, pubKeyDHBuffer.data());

    cout << "***********************************" << endl;

    memcpy(nonceClient_t.data(), nonceClient.data(), constants::NONCE_SIZE);

    byte_index = 0;   
    memset(clear_buf, 0, dim);
    free(clear_buf);

    secureSum(pubKeyDHBufferLen, sizeof(char) + constants::NONCE_SIZE + sizeof(int));
    dim = sizeof(char) + constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferLen;

    message_sent = (unsigned char*)malloc(dim);
    if(!message_sent) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    secureSum(pubKeyDHBufferLen, sizeof(char) + constants::NONCE_SIZE + constants::NONCE_SIZE + sizeof(int));
    memcpy(&(message_sent[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message_sent[byte_index]), nonceServer.data(), nonceServer.size());
    byte_index += constants::NONCE_SIZE;

    memcpy(&(message_sent[byte_index]), &pubKeyDHBufferLen, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message_sent[byte_index]), pubKeyDHBuffer.data(), pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;

    message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    if(!message_signed) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    signed_size = 0;
    signed_size = clt.crypto->digsign_sign(message_sent, dim, message_signed, user_key);
    if(signed_size < 0){
        cerr << RED << "[ERROR] invalid signature!" << endl;
        return false;
    } else { 
        cout << GREEN << "[LOG] valid Signature " << RESET << endl;
    }

    clt.clientConn->send_message(message_signed, signed_size);

    free(signature);

    clt.crypto->deserializePublicKey(pubKeyDHBufferServer.data(), pubKeyDHBufferServerLen, pubKeyDHServer);

    cout << GREEN << "[LOG] Generating session key " << RESET << endl;

    clt.crypto->secretDerivation(prvKeyDHClient, pubKeyDHServer, tempBuffer.data());
    clt.clientConn->addSessionKey(tempBuffer.data());

    cout << CYAN << "[LOG] Authentication succeeded " << RESET << endl;

    memset(tempBuffer.data(), 0, tempBuffer.size());
    free(message_sent);
    free(message_received);

    return true;
}

int receiveRequestToTalk(Client &clt, unsigned char* msg, int msg_len, unsigned char *myNonce_save){
    unsigned int keyBufferDHLen = 0;
    EVP_PKEY *keyDH = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> keyDHBuffer;
    vector<unsigned char> decrypted;
    vector<unsigned char> encrypted; 
    int byte_index = 0;
    unsigned char* username = NULL;
    int username_size = 0;
    unsigned char* response_to_request = NULL;
    unsigned char* response_to_sign = NULL;
    vector<unsigned char> buffer;
    unsigned char response = 'n';
    int dim = 0;
    int dim_to_sign = 0;
    int signed_size = 0;
    EVP_PKEY* user_key = NULL;

    array<unsigned char, constants::NONCE_SIZE> nonceClient;
    array<unsigned char, constants::NONCE_SIZE> myNonce_t;
    array<unsigned char, constants::NONCE_SIZE> myNonce;

    string filename = "./keys/private/" + clt.clientConn->getUsernameS() + "_prvkey.pem";

	FILE* file = fopen(filename.c_str(), "r");
	if(!file) {
        cerr << RED << "[ERROR] User does not have a key file" << RESET << endl; 
        exit(1);
    }   

	user_key = PEM_read_PrivateKey(file, NULL, NULL, (void*)clt.clientConn->getPassword().c_str());
	if(!user_key) {
        cerr << RED << "[ERROR] Password not valid, retry" << RESET << endl; 
        return false;
    }

	fclose(file);

    clt.crypto->decryptMessage(clt.clientConn->getSessionKey(), msg, msg_len, decrypted, clt.clientConn->getSessionClientServer());

    byte_index += sizeof(char);

    memcpy(&(username_size), &decrypted.data()[byte_index], sizeof(int));
    byte_index += sizeof(int);

    if(username_size < 0 || username_size > constants::MAX_MESSAGE_SIZE) {
        cerr << RED << "[ERROR] username size error" << RESET << endl;
        return -1;
    }

    username = (unsigned char*)malloc(username_size);
    if(username == NULL) {
        cerr << RED << "[ERROR] username malloc error" << RESET << endl;
        return -1;
    }

    memcpy(username, &decrypted.data()[byte_index], username_size);
    byte_index += username_size;

    memcpy(nonceClient.data(), &decrypted.data()[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    unsigned char* username_to_copy = clt.clientConn->getUsername();
    if(!username_to_copy) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    } 

    int username_to_copy_size = clt.clientConn->getUsernameSize();

    if( (username_size == username_to_copy_size) && memcmp(username_to_copy, username, username_size) == 0) {
        cout << RED << "[ERROR] you're trying to speak with yourself, insert a valid username" << RESET << endl;
        return -1;
    }
   
    cout << "Do you want to talk with ";
    for(int i = 0; i < username_size; i++) {
        cout << username[i];
    }
    cout << "? (y/n)" << endl;

    cin >> response;
    cin.ignore();

    // Messaggio con chiave pubblica DH
    if(response == 'y') {

        cout << GREEN << "[LOG] starting the chat" << RESET << endl;

        clt.clientConn->setCurrentChat(username, username_size, username_to_copy, username_to_copy_size);

        //nonce generation

        clt.crypto->generateNonce(myNonce.data());

        // conservo il nonce per verificarlo al passo successivo
        memcpy(myNonce_t.data(), myNonce.data(), constants::NONCE_SIZE);
        memcpy(&myNonce_save[0], myNonce.data(), constants::NONCE_SIZE);

        clt.crypto->keyGeneration(keyDH);
        keyBufferDHLen = clt.crypto->serializePublicKey(keyDH, keyDHBuffer.data());

        clt.clientConn->setKeyDHBufferTemp(keyDH, keyBufferDHLen);

        secureSum(keyBufferDHLen, constants::NONCE_SIZE);
        dim_to_sign =  constants::NONCE_SIZE + keyBufferDHLen;

        response_to_sign = (unsigned char*)malloc(dim_to_sign); 
        if(response_to_sign == NULL) {
            cerr << RED << "[ERROR] malloc response error" << RESET << endl;
            return -1;
        }

        //Preparare messaggio da firmare in response_to_sign
        byte_index = 0;
        secureSum(keyBufferDHLen, constants::NONCE_SIZE);

        memcpy(&(response_to_sign[byte_index]), keyDHBuffer.data(), keyBufferDHLen);
        byte_index += keyBufferDHLen;

        memcpy(&(response_to_sign[byte_index]), nonceClient.data(), constants::NONCE_SIZE);
        byte_index += constants::NONCE_SIZE;

        //Aggiungere firma
        unsigned char* message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
        if(!message_signed) {
            cerr << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        signed_size = 0;
        // signed size = dim(keyDHBuffer + nonce) + dim firma + firma
        signed_size = clt.crypto->digsign_sign(response_to_sign, dim_to_sign, message_signed, user_key);
        if(signed_size < 0){
            cerr << RED << "[ERROR] invalid signature!" << endl;
            return false;
        } else { 
            cout << GREEN << "[LOG] valid Signature " << RESET << endl;
        }
        

        const char* message_signed_t = reinterpret_cast<const char *>(message_signed);

        secureSum(signed_size, sizeof(char) + constants::NONCE_SIZE + sizeof(int)*2);
        dim = sizeof(char) + constants::NONCE_SIZE + sizeof(int)*2 + signed_size;
        response_to_request = (unsigned char*)malloc(dim); 
        if(response_to_request == NULL) {
            cerr << RED << "[ERROR] malloc response error" << RESET << endl;
            return -1;
        }

        //OPCODE | mynonce | pubKeyDH | nonceA | signature (nonceA, pubkeyDH)
        
        byte_index = 0;
        secureSum(signed_size, sizeof(char) + constants::NONCE_SIZE);
        
        memcpy(&(response_to_request[byte_index]), &constants::ACCEPTED, sizeof(char));
        byte_index += sizeof(char);

        memcpy(&(response_to_request[byte_index]), myNonce.data(), constants::NONCE_SIZE);
        byte_index += constants::NONCE_SIZE;


        memcpy(&(response_to_request[byte_index]), &keyBufferDHLen, sizeof(int));
        byte_index += sizeof(int);


        memcpy(&(response_to_request[byte_index]), message_signed_t, sizeof(int) + signed_size);
        byte_index += signed_size + sizeof(int);


        cout << "***********************************" << endl;

    } else {
        cout << RED << "refused :(" << RESET << endl;

        dim = sizeof(char);

        response_to_request = (unsigned char*)malloc(dim); 
        if(response_to_request == NULL) {
            cerr << RED << "[ERROR] malloc response error" << RESET << endl;
            return -1;
        }

        byte_index = 0;
        memcpy(&(response_to_request[byte_index]), &constants::REFUSED, sizeof(char));
        byte_index += sizeof(char);

        int ret = send_message_enc(clt.clientConn->getMasterFD(), clt, response_to_request, dim, encrypted, clt.clientConn->getSessionClientServer());
        if(ret <= 0) {
            return -1;
        }

        free(response_to_request);
        free(username);

        return 0;
    }  

    int ret = send_message_enc(clt.clientConn->getMasterFD(), clt, response_to_request, dim, encrypted, clt.clientConn->getSessionClientServer());
    if(ret <= 0) {
        return -1;
    }

    free(response_to_request);
    free(username);

    return 1;
}

void print_unsigned_array(unsigned char* array, int dim) {
    for(int i = 0; i < dim; i++) {
        cout << array[i];
    }
}

void startingChat(Client clt, vector<unsigned char> packet, unsigned char* myNonce) {

    vector<unsigned char> decrypted;
    int peerKeyDHLen = 0;
    unsigned char* peerKeyDHBuffer = NULL;
    int peerPubKeyLen = 0;
    unsigned char* peerPubKeyBuffer = NULL; 
    EVP_PKEY* peerKeyDH = NULL;
    array<unsigned char, constants::NONCE_SIZE> myNonce_rec;
    int signature_size = 0;
    int dim = 0;
    unsigned char* signature = NULL;
    packet.clear();
    packet.resize(constants::MAX_MESSAGE_SIZE);
    int received_size = receive_message_enc(clt, packet.data(), decrypted, clt.clientConn->getSessionClientServer());
    if(received_size < 0) {
        cout << RED << "[ERROR] receive error" << RESET << endl;
        exit(1);
    }

    packet.clear();

    int byte_index = sizeof(char);

    memcpy(&(peerKeyDHLen), &decrypted.data()[byte_index], sizeof(int));
    byte_index += sizeof(int);

    peerKeyDHBuffer = (unsigned char*)malloc(peerKeyDHLen);
    if(!peerKeyDHBuffer) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }
   
    secureSum(constants::NONCE_SIZE, peerKeyDHLen);
    dim = constants::NONCE_SIZE + peerKeyDHLen;

    unsigned char* clear_buf = (unsigned char*)malloc(dim);
    if(!clear_buf) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(peerKeyDHBuffer, &decrypted.data()[byte_index], peerKeyDHLen);
    memcpy(clear_buf, &decrypted.data()[byte_index], peerKeyDHLen + constants::NONCE_SIZE);
    byte_index += peerKeyDHLen;

    clt.crypto->deserializePublicKey(peerKeyDHBuffer, peerKeyDHLen, peerKeyDH);

    memcpy(myNonce_rec.data(), &decrypted.data()[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(peerPubKeyLen), &decrypted.data()[byte_index], sizeof(int));
    byte_index += sizeof(int);

    peerPubKeyBuffer = (unsigned char*)malloc(peerPubKeyLen);
    if(!peerPubKeyBuffer) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(peerPubKeyBuffer, &decrypted.data()[byte_index], peerPubKeyLen);
    byte_index += peerPubKeyLen;

    clt.crypto->deserializePublicKey(peerPubKeyBuffer, peerPubKeyLen, clt.clientConn->getMyCurrentChat()->pubkey_2);

    //Prendere la firma


    memcpy(&(signature_size), &decrypted.data()[byte_index], sizeof(int));
    byte_index += sizeof(int);


    signature = (unsigned char*)malloc(signature_size);
    if(!signature) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }
    
    memcpy(signature, &decrypted.data()[byte_index], signature_size);
    byte_index += signature_size;

    cout << "Pure qui!" <<endl;
    //Verificare firma

    unsigned int verify = clt.crypto->digsign_verify(signature, signature_size, clear_buf, sizeof(int), clt.clientConn->getMyCurrentChat()->pubkey_2);
    if(verify < 0){
        cerr << RED << "[ERROR] invalid signature!" << endl;
        exit(1);
    } else { 
        cout << GREEN << "[LOG] valid Signature " << RESET << endl;
    }

    // Verificare nonce
    if(memcmp(myNonce, myNonce_rec.data(), constants::NONCE_SIZE) != 0){
        cerr << RED << "[ERROR] nonce received is not valid!" << RESET << endl;
        exit(1);
    } else {
        cout << GREEN << "[LOG] nonce verified " << RESET << endl;
    }


    // Costruire chiave di sessione prvDH
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;

    clt.crypto->secretDerivation(clt.clientConn->getKeyDHBufferTemp(), peerKeyDH, tempBuffer.data());
    memcpy(clt.clientConn->getMyCurrentChat()->chat_key, tempBuffer.data(), EVP_MD_size(EVP_sha256()));

    if(!clt.clientConn->getMyCurrentChat()->chat_key) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);    
    }
}

void chat(Client clt) {

    fd_set fds;
    string message;
    unsigned char* to_send = NULL;
    vector<unsigned char> encrypted;
    vector<unsigned char> decrypted;
    vector<unsigned char> clear;
    unsigned char* buffer = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);

    if(!buffer) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        return;
    }

    unsigned char* iv = (unsigned char*)malloc(constants::IV_LEN);
    if(!iv) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        return;
    }

    int maxfd;
    int ret = -1;

    cout << "---------------------------------------" << endl;
    cout << "\n-------Chat-------" << endl;
    cout << "you can insert ':q!' to exit the chat!" << endl;
    cout << "---------------------------------------" << endl;

    while(1) {

        decrypted.clear();
        encrypted.clear();

        memset(buffer, 0, constants::MAX_MESSAGE_SIZE);

        maxfd = (clt.clientConn->getMasterFD() > STDIN_FILENO) ? clt.clientConn->getMasterFD() : STDIN_FILENO;
        FD_ZERO(&fds);
        FD_SET(clt.clientConn->getMasterFD(), &fds); 
        FD_SET(STDIN_FILENO, &fds); 
        
        select(maxfd + 1, &fds, NULL, NULL, NULL); 

        if(FD_ISSET(0, &fds)) {  
            cout << "\n ";
            getline(cin, message);
            cout << endl;

            int byte_index = 0;
            unsigned char* tempBuffer;
            int dim = 0;

            if(message.compare(":q!") == 0) {
                cout << MAGENTA << "[LOG] user ending the chat" << RESET << endl;
                dim = sizeof(char);
            } else {
                dim = sizeof(char) + message.size();
            }

            tempBuffer = (unsigned char*)malloc(dim);
            if(!tempBuffer) {
                cerr << RED << "[ERROR] malloc error" << RESET << endl;
                return;
            }

            if(message.compare(":q!") == 0) {
                memcpy(&(tempBuffer[byte_index]), &constants::REFUSED, sizeof(char));
                byte_index += sizeof(char);
            } else {
                secureSum(sizeof(char), message.size());
                memcpy(&(tempBuffer[byte_index]), &constants::CHAT, sizeof(char));
                byte_index += sizeof(char);

                memcpy(&(tempBuffer[byte_index]), message.c_str(), message.size());
                byte_index += message.size();
            }

            // la prima volta che cifro, lo sto facendo con la session key, quindi devo mettere come contatore quello tra client e client
            clt.clientConn->generateIV(iv);
            int encrypted_size = clt.crypto->encryptMessage(clt.clientConn->getMyCurrentChat()->chat_key, iv, tempBuffer, dim, encrypted, clt.clientConn->getSessionClientClient());
            if(encrypted_size < 0 || encrypted_size > constants::MAX_MESSAGE_SIZE) {
                cout << RED << "[ERROR] message not valid" << RESET << endl;
                exit(1);
            }

            byte_index = 0;
            to_send = (unsigned char*)malloc(encrypted_size);
            if(!to_send) {
                cout << RED << "[ERROR] malloc error" << RESET << endl;
                exit(1);
            }

            memcpy(&(to_send[byte_index]), encrypted.data(), encrypted_size);
            byte_index += encrypted_size;

            encrypted.clear();

            ret = send_message_enc(clt.clientConn->getMasterFD(), clt, to_send, encrypted_size, encrypted, clt.clientConn->getSessionClientServer());

            if(ret <= 0) {
                cerr << RED << "[ERROR] error during the send encrypted" << RESET << endl;
                return;
            }

            if(message.compare(":q!") == 0) {
                cout << MAGENTA << "[LOG] chat ended" << RESET << endl;
                message.clear();
                exit(1);
            }
        }

        // arrivo di un messaggio da parte dell'altro client
        if(FD_ISSET(clt.clientConn->getMasterFD(), &fds)) {
            
            ret = receive_message_enc(clt, buffer, decrypted, clt.clientConn->getSessionClientServer());

            int decrypted_size = clt.crypto->decryptMessage(clt.clientConn->getMyCurrentChat()->chat_key, decrypted.data(), ret, clear, clt.clientConn->getSessionClientClient());

            cout << BLUE;

            if( (clt.clientConn->getUsernameSize() ==  clt.clientConn->getMyCurrentChat()->dim_us1) && memcmp(clt.clientConn->getMyCurrentChat()->username_1, clt.clientConn->getUsername(), clt.clientConn->getMyCurrentChat()->dim_us1) == 0) {
                print_unsigned_array(clt.clientConn->getMyCurrentChat()->username_2, clt.clientConn->getMyCurrentChat()->dim_us2);
            } else if( (clt.clientConn->getUsernameSize() == clt.clientConn->getMyCurrentChat()->dim_us2) && memcmp(clt.clientConn->getMyCurrentChat()->username_2, clt.clientConn->getUsername(), clt.clientConn->getMyCurrentChat()->dim_us2) == 0) {
                print_unsigned_array(clt.clientConn->getMyCurrentChat()->username_1, clt.clientConn->getMyCurrentChat()->dim_us1);
            } else {
                cout << RED << "[ERROR] username not found" << RESET << endl;
                exit(1);
            }

            cout << ": " << endl;

            // output dei messaggi inviati: 
            /*
                *********
                message *
                *********
            */

            if(decrypted.at(0) == constants::REFUSED) {
                // the other user want to end the chat
                cout << "wants to end the chat.. disconnecting" << RESET << endl;
                exit(1);
            }

            int limit = decrypted_size + 2;

            for(int i = 0; i < limit ; i++) {
                cout << "*";
            }
            cout << RESET << endl;

            for(int i = sizeof(char); i < decrypted_size; i++) {
                cout << clear.data()[i];
            }

            cout << BLUE << " *" << endl;

            for(int i = 0; i < limit; i++) {
                cout << "*";
            }

            cout << RESET << endl;
        }
    }
}

void sendRequestToTalk(Client clt, string username_to_contact, string username) {
    int byte_index = 0;  
    int peerPubKeyLen = 0;
    int peerKeyDHLen = 0;
    unsigned char* peerKeyDHBuffer = NULL;
    unsigned char* peerPubKeyBuffer = NULL;
    EVP_PKEY *peerKeyDH = NULL;
    EVP_PKEY *keyDH = NULL;
    array<unsigned char, constants::MAX_MESSAGE_SIZE> keyDHBuffer;
    int keyDHBufferLen = 0;
    vector<unsigned char> encrypted;
    vector<unsigned char> decrypted;
    int signature_size = 0;
    int dim_to_sign;
    unsigned char* response_to_sign;
    unsigned char* signature = NULL;
    array<unsigned char, constants::NONCE_SIZE> nonceClient;
    array<unsigned char, constants::NONCE_SIZE> myNonce_rec;
    array<unsigned char, constants::NONCE_SIZE> myNonce_t;
    array<unsigned char, constants::NONCE_SIZE> myNonce;
    EVP_PKEY* user_key = NULL;

    string filename = "./keys/private/" + clt.clientConn->getUsernameS() + "_prvkey.pem";

	FILE* file = fopen(filename.c_str(), "r");
	if(!file) {
        cerr << RED << "[ERROR] User does not have a key file" << RESET << endl; 
        exit(1);
    }   

	user_key = PEM_read_PrivateKey(file, NULL, NULL, (void*)clt.clientConn->getPassword().c_str());
	if(!user_key) {
        cerr << RED << "[ERROR] Password not valid, retry" << RESET << endl; 
        exit(1);
    }

	fclose(file);

    // M1 OPCODE | sizeof(username) | username | nonceA

     clt.crypto->generateNonce(myNonce.data());

    // conservo il nonce per verificarlo al passo successivo
    memcpy(myNonce_t.data(), myNonce.data(), constants::NONCE_SIZE);

    int dim = sizeof(char) + sizeof(int) + username_to_contact.size() + constants::NONCE_SIZE;
    unsigned char* message = (unsigned char*)malloc(dim); 
    if(!message) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    } 

    secureSum(username_to_contact.size(), sizeof(int) + sizeof(char) + constants::NONCE_SIZE);
    memcpy(&(message[byte_index]), &constants::REQUEST, sizeof(char));
    byte_index += sizeof(char);

    int username_to_contact_size = username_to_contact.size();
    memcpy(&(message[byte_index]), &username_to_contact_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), username_to_contact.c_str(), username_to_contact.size());
    byte_index += username_to_contact.size();

    memcpy(&(message[byte_index]), myNonce.data(), nonceClient.size());
    byte_index += myNonce.size();

    int ret = send_message_enc(clt.clientConn->getMasterFD(), clt, message, dim, encrypted, clt.clientConn->getSessionClientServer());
    if(ret <= 0) {
        return;
    }

    unsigned char* response = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    if(!response) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    } 

    cout << "*** waiting for response *** " << endl;

    ret = receive_message_enc(clt, response, decrypted, clt.clientConn->getSessionClientServer());
    //cout <<"Ricevuto!"<<endl;
    if (ret == 0) {
        cout << RED << "[LOG] client connection closed" << RESET << endl;
        free(response);
        return;
    } 

    // request to talk accettata, avvio la chat
    if(response[0] == constants::ACCEPTED) {

        // Mettere dopo

        clt.clientConn->setCurrentChat((unsigned char*)username_to_contact.c_str(), username_to_contact.size(), (unsigned char*)username.c_str(), username.size());

        byte_index = 0;
        byte_index += sizeof(char);


        //Nonce di B da tenere e riutilizzare

        memcpy(nonceClient.data(), &decrypted.data()[byte_index], constants::NONCE_SIZE);
        byte_index += constants::NONCE_SIZE;

        memcpy(&(peerKeyDHLen), &decrypted.data()[byte_index], sizeof(int));
        byte_index += sizeof(int);


        peerKeyDHBuffer = (unsigned char*)malloc(peerKeyDHLen);
        if(!peerKeyDHBuffer) {
            cout << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        secureSum(constants::NONCE_SIZE, peerKeyDHLen);
        dim = constants::NONCE_SIZE + peerKeyDHLen;

         unsigned char* clear_buf = (unsigned char*)malloc(dim);
        if(!clear_buf) {
            cerr << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        memcpy(peerKeyDHBuffer, &decrypted.data()[byte_index], peerKeyDHLen);
        memcpy(clear_buf, &decrypted.data()[byte_index], peerKeyDHLen + constants::NONCE_SIZE);
        byte_index += peerKeyDHLen;

        clt.crypto->deserializePublicKey(peerKeyDHBuffer, peerKeyDHLen, peerKeyDH);

        //Nonce mio da verificare
        memcpy(myNonce_rec.data(), &decrypted.data()[byte_index], constants::NONCE_SIZE);
        byte_index += constants::NONCE_SIZE;
       
        //Chiave pubblica di B
        memcpy(&(peerPubKeyLen), &decrypted.data()[byte_index], sizeof(int));
        byte_index += sizeof(int);

        peerPubKeyBuffer = (unsigned char*)malloc(peerPubKeyLen);
        if(!peerPubKeyBuffer) {
            cout << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        memcpy(peerPubKeyBuffer, &decrypted.data()[byte_index], peerPubKeyLen);
        byte_index += peerPubKeyLen;

        secureSum(peerKeyDHLen, signature_size + sizeof(int)*2 + sizeof(char) + constants::NONCE_SIZE);

        clt.crypto->deserializePublicKey(peerPubKeyBuffer, peerPubKeyLen, clt.clientConn->getMyCurrentChat()->pubkey_1);

         //Dimensione firma e firma

        memcpy(&(signature_size), &decrypted.data()[byte_index], sizeof(int));
        byte_index += sizeof(int);

        signature = (unsigned char*)malloc(signature_size);
        if(!signature) {
            cerr << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }
        
        memcpy(signature, &decrypted.data()[byte_index], signature_size);
        byte_index += signature_size;

        //Verificare firma di B
        unsigned int verify = clt.crypto->digsign_verify(signature, signature_size, clear_buf, sizeof(int), clt.clientConn->getMyCurrentChat()->pubkey_1);
        if(verify < 0){
            cerr << RED << "[ERROR] invalid signature!" << endl;
            exit(1);
        } else { 
            cout << GREEN << "[LOG] valid Signature " << RESET << endl;
        }

        // Verificare nonce
        if(memcmp(myNonce_t.data(), myNonce_rec.data(), constants::NONCE_SIZE) != 0){
            cerr << RED << "[ERROR] nonce received is not valid!" << RESET << endl;
            exit(1);
        } else {
            cout << GREEN << "[LOG] nonce verified " << RESET << endl;
        }

        // Costruire chiave di sessione prvDH
        array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;

        clt.crypto->keyGeneration(keyDH);
        clt.crypto->secretDerivation(keyDH, peerKeyDH, tempBuffer.data());

        memcpy(clt.clientConn->getMyCurrentChat()->chat_key, tempBuffer.data(), EVP_MD_size(EVP_sha256()));
        if(!clt.clientConn->getMyCurrentChat()->chat_key) {
            cout << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);    
        }

        //Costruire e inviare mia chiave DH
        // opcode | keyDH | nonce B (nonceclient) | firma (keyDH e nonce B)

        keyDHBufferLen = clt.crypto->serializePublicKey(keyDH, keyDHBuffer.data());

        secureSum(keyDHBufferLen, constants::NONCE_SIZE);
        dim_to_sign =  constants::NONCE_SIZE + keyDHBufferLen;

        response_to_sign = (unsigned char*)malloc(dim_to_sign); 
       
        if(response_to_sign == NULL) {
            cerr << RED << "[ERROR] malloc response error" << RESET << endl;
            exit(1);
        }

        //Preparare messaggio da firmare in response_to_sign

        byte_index = 0;

        memcpy(&(response_to_sign[byte_index]), keyDHBuffer.data(), keyDHBufferLen);
        byte_index += keyDHBufferLen;

        memcpy(&(response_to_sign[byte_index]), nonceClient.data(), constants::NONCE_SIZE);
        byte_index += constants::NONCE_SIZE;

        //Firmare
        unsigned char* message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
        if(!message_signed) {
            cerr << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        int signed_size = 0;
        signed_size = clt.crypto->digsign_sign(response_to_sign, dim_to_sign, message_signed, user_key);
        if(signed_size < 0){
            cerr << RED << "[ERROR] invalid signature!" << endl;
            exit(1);
        } else { 
            cout << GREEN << "[LOG] valid Signature " << RESET << endl;
        }
          
        free(message);

        secureSum(keyDHBufferLen, sizeof(char) + constants::NONCE_SIZE + sizeof(int)*2 + signed_size);
        dim = sizeof(char) + sizeof(int)*2 + keyDHBufferLen + constants::NONCE_SIZE + signed_size;

        message = (unsigned char*)malloc(dim); 
        if(message == NULL) {
            cout << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        byte_index = 0;

        memcpy(&(message[byte_index]), &constants::ACCEPTED, sizeof(char));
        byte_index += sizeof(char);

        memcpy(&(message[byte_index]), &keyDHBufferLen, sizeof(int));
        byte_index += sizeof(int);

        const char* message_signed_t = reinterpret_cast<const char *>(message_signed);

        memcpy(&(message[byte_index]), message_signed_t, signed_size + sizeof(int));
        byte_index += signed_size + sizeof(int);

        //Inviare ultimo messaggio
        encrypted.clear();
        ret = send_message_enc(clt.clientConn->getMasterFD(), clt, message, byte_index, encrypted, clt.clientConn->getSessionClientServer());
        if(ret <= 0) {
            return;
        }

        chat(clt);

        cout << "------------------" << endl;
    } else {
        cout << RED << "we're sorry, your request was rejected :'(" << RESET << endl;
    }

    free(response);
}

void logout(Client clt) {
    cout << RED << "--- LOGOUT ---" << RESET << endl;
    int byte_index = 0;    

    int dim = sizeof(char);
    unsigned char* message = (unsigned char*)malloc(dim);  
    if(message == NULL) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(&(message[byte_index]), &constants::LOGOUT, sizeof(char));
    byte_index += sizeof(char);
    clt.clientConn->send_message(message, dim);

    free(message);
}

void seeOnlineUsers(Client clt, vector<unsigned char> &buffer){

    int byte_index = 0;    
    vector<unsigned char> encrypted;

    int dim = sizeof(char);
    unsigned char* message = (unsigned char*)malloc(dim);  
    if(message == NULL) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(&(message[byte_index]), &constants::ONLINE, sizeof(char));
    byte_index += sizeof(char);
    
    int ret = send_message_enc(clt.clientConn->getMasterFD(), clt, message, dim, encrypted, clt.clientConn->getSessionClientServer());

    free(message);
    buffer.clear();
    unsigned char* message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    if(message_received == NULL) {
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    } 

    clt.clientConn->generateIV();
    ret = receive_message_enc(clt, message_received, buffer, clt.clientConn->getSessionClientServer());

    if (ret == 0) {
        cout << RED << "[LOG] client connection closed" << RESET << endl;
        buffer.clear();
        return;
    } else {
        cout << GREEN << "[LOG] list received" << RESET << endl;
    }

    byte_index = 0;    

    char opCode;
    int list_size = 0; 
    int dim_message = 0;

    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(dim_message), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(list_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);
    
    //Se list_size == 0 non ci sono utenti online
    if(list_size == 0) {
        cout << RED << "--- no user online ---" << RESET << endl;
    } else {
        cout << "--- online users ---" << endl;

        cout << GREEN << " | ";

        for(int i = 0; i < list_size; i++) {
            int username_size = 0;

            memcpy(&(username_size), &buffer[byte_index], sizeof(int));
            byte_index += sizeof(int);

            unsigned char* username = (unsigned char*)malloc(username_size);
            if(username == NULL) {
                cout << RED << "[ERROR] malloc error" << RESET << endl;
                exit(1);
            } 
            
            memcpy(username, &buffer[byte_index], username_size);
            byte_index += username_size;

            for(int j = 0; j < username_size; j++) {
                cout << username[j];
            }

            if( i + 1 == list_size )
                cout << " | ";
            else
                cout << " - ";

            free(username);
        }

        cout << RESET << endl;
    }

    buffer.clear();
}
