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
    string username;  
};

string readMessage() {
    string message;
    getline(cin, message);
    if (message.length() > constants::MAX_MESSAGE_SIZE) {
        cerr << "Error: the message must be loger than " << endl;
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

int send_message_enc(int masterFD, Client clt, unsigned char* message, int dim, vector<unsigned char> &encrypted) {
    int ret = 0;

    printf("sending encrypted is:\n");
    BIO_dump_fp(stdout, (const char*)message, dim);

    printf("key is:\n");
    BIO_dump_fp(stdout, (const char*)clt.clientConn->getSessionKey(), 16);

    clt.clientConn->generateIV();

    printf("iv is:\n");
    BIO_dump_fp(stdout, (const char*)clt.clientConn->getIV(), constants::IV_LEN);

    encrypted.resize(dim);
    int encrypted_size = clt.crypto->encryptMessage(clt.clientConn->getSessionKey(), clt.clientConn->getIV(), message, dim, encrypted);

    printf("encrypted send is:\n");
    BIO_dump_fp(stdout, (const char*)encrypted.data(), encrypted_size);

    do {
        ret = send(masterFD, encrypted.data(), encrypted_size, 0);
        if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            perror("Send Error");
            throw runtime_error("Send failed");
        } else if (ret == 0) {
            cout << "client connection closed" << endl;
            return -1;
        } 
    } while (ret != encrypted_size);

    return ret;
}

int receive_message_enc(Client clt, unsigned char* message, vector<unsigned char> &decrypted) {
    int message_len;

    do {
        message_len = recv(clt.clientConn->getMasterFD(), message, constants::MAX_MESSAGE_SIZE-1, 0);
        
        if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            perror("Receive Error");
            throw runtime_error("Receive failed");
        } else if (message_len == 0) {
            cout << "client connection closed" << endl;
            return 0;
        } 
    } while (message_len < 0);

    printf("ciphertext is:\n");
    BIO_dump_fp(stdout, (const char*)message, message_len);

    printf("1) session key is:\n");
    BIO_dump_fp(stdout, (const char*)clt.clientConn->getSessionKey(), 16);

    printf("iv is:\n");
    BIO_dump_fp(stdout, (const char*)clt.clientConn->getIV(), constants::IV_LEN);

    int decrypted_size = clt.crypto->decryptMessage(clt.clientConn->getSessionKey(), clt.clientConn->getIV(), message, message_len, decrypted);

    return decrypted_size;
}

bool authentication(Client &clt, string username, string password) {
    X509 *cert;
    EVP_PKEY* user_key = NULL;
    EVP_PKEY *pubKeyServer = NULL;
    EVP_PKEY *pubKeyDHServer = NULL;
    EVP_PKEY *prvKeyDHClient = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    unsigned int pubKeyDHBufferLen;
    vector<unsigned char> buffer;
    unsigned char* nonceServer = (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* nonceClient_rec = (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* nonceClient_t = (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* signature = NULL;
    string to_insert;
    array<unsigned char, NONCE_SIZE> nonceClient;
    clt.username = username;

    string filename = "./keys/private/" + username + "_prvkey.pem";
	
	FILE* file = fopen(filename.c_str(), "r");
	if(!file) {
        cerr << "User does not have a key file" << endl; 
        exit(1);
    }   

	user_key = PEM_read_PrivateKey(file, NULL, NULL, (void*)password.c_str());
	if(!user_key) {
        cerr << "User does not valid, retry..." << endl; 
        return false;
    }

	fclose(file);
    
    clt.crypto->generateNonce(nonceClient.data());

    // conservo il nonce per verificarlo al passo successivo
    memcpy(nonceClient_t, nonceClient.data(), constants::NONCE_SIZE);

    int byte_index = 0;   

    int dim = sizeof(char) + sizeof(int) + username.size() + nonceClient.size();

    unsigned char* message_sent = (unsigned char*)malloc(dim);      

    memcpy(&(message_sent[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    int username_size = username.size();
    memcpy(&(message_sent[byte_index]), &username_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message_sent[byte_index]), username.c_str(), username.size());
    byte_index += username.size();

    memcpy(&(message_sent[byte_index]), nonceClient.data(), nonceClient.size());
    byte_index += nonceClient.size();

    unsigned char* message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    int signed_size = clt.crypto->digsign_sign(message_sent, dim, message_signed, user_key);

    clt.clientConn->send_message(message_signed, signed_size);

    free(message_sent);
    free(message_signed);

    // ricevere certificato
    unsigned char* message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    int ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), message_received);
    if(ret == 0) {
        cout << RED << "** client connection closed **" << RESET << endl;
        free(message_received);
        return false;
    }

    byte_index = 0;
    signed_size = 0;
    char opcode;
    size_t size_cert = 0;

    memcpy(&(opcode), &message_received[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(size_cert), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* cert_buf = (unsigned char*)malloc(size_cert);
    if(!cert_buf) {
        cerr << "Malloc error on certification buffer" << endl; 
        exit(1);
    }

    memcpy(cert_buf, &message_received[byte_index], size_cert);
    byte_index += size_cert;

    nonceServer = (unsigned char*)malloc(constants::NONCE_SIZE);
    if(!nonceServer) {
        cerr << "Malloc error on nonce server" << endl; 
        exit(1);
    }

    memcpy(nonceServer, &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(nonceClient_rec, &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    
    memcpy(&(signed_size), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);
    
    signature = (unsigned char*)malloc(signed_size);
    memcpy(signature, &message_received[byte_index], signed_size);
    byte_index += signed_size;

    cert = d2i_X509(NULL, (const unsigned char**)&cert_buf, size_cert);

    if(!clt.crypto->verifyCertificate(cert)) {
        cerr << "Error in certificate verification" << endl; 
        exit(1);
    }
    
    cout << GREEN << "Server certificate verified" << RESET << endl;  

    // print the successful verification to screen, just for debug
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    cout << CYAN << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n" << RESET << endl;
    free(tmp);
    free(tmp2);

    clt.crypto->getPublicKeyFromCertificate(cert, pubKeyServer);

    byte_index = 0;
    dim = sizeof(char) + sizeof(int) + size_cert + constants::NONCE_SIZE + constants::NONCE_SIZE; 
    unsigned char* clear_buf = (unsigned char*)malloc(dim);

    memcpy(clear_buf, &message_received[byte_index], dim);
    byte_index += sizeof(char);

    int sign_size = 0;
    memcpy(&sign_size, &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* sign = (unsigned char*)malloc(sign_size);
    memcpy(sign, &message_received[byte_index], sign_size);
    byte_index += sign_size;
    
    unsigned int verify = clt.crypto->digsign_verify(sign, sign_size, clear_buf, sizeof(int), pubKeyServer);
    if(verify < 0){
        cerr << "Invalid signature!" << endl;
        return false;
    } else { 
        cout << GREEN << "** Valid Signature **" << RESET << endl;
    }

    //Verificare nonce

    cout << "Nonce: " << endl;
    for(int i = 0; i < constants::NONCE_SIZE; i++) {
        cout << nonceClient_t[i];
    }

    cout << " | ";

    for(int i = 0; i < constants::NONCE_SIZE; i++) {
        cout << nonceClient_rec[i];
    }
    cout << endl;
    cout << endl;

    if(memcmp(nonceClient_t, nonceClient_rec, constants::NONCE_SIZE) != 0){
        cerr << "Nonce received is not valid!" << endl;
        exit(1);
    } else {
        cout << GREEN << "** Nonce verified **" << RESET << endl;
    }

    // -- SCAMBIO CHIAVE DI SESSIONE -- 

    clt.crypto->generateNonce(nonceClient.data());

    clt.crypto->keyGeneration(prvKeyDHClient);
    pubKeyDHBufferLen = clt.crypto->serializePublicKey(prvKeyDHClient, pubKeyDHBuffer.data());

    cout << "***********************************" << endl;

    memcpy(nonceClient_t, nonceClient.data(), constants::NONCE_SIZE);

    byte_index = 0;   

    // OPCODE | New_nonce_client | Nonce Server | Pub_key_DH_len | pub_key_DH | dig_sign

    dim = sizeof(char) + constants::NONCE_SIZE + constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferLen;

    message_sent = (unsigned char*)malloc(dim);
    if(!message_sent) {
        throw runtime_error("Malloc error");
    }

    memcpy(&(message_sent[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message_sent[byte_index]), nonceClient.data(), nonceClient.size());
    byte_index += constants::NONCE_SIZE;

    memcpy(&(message_sent[byte_index]), nonceServer, constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(message_sent[byte_index]), &pubKeyDHBufferLen, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message_sent[byte_index]), pubKeyDHBuffer.data(), pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;

    //Aggiungere firma

    message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    signed_size = 0;
    signed_size = clt.crypto->digsign_sign(message_sent, dim, message_signed, user_key);

    clt.clientConn->send_message(message_signed, signed_size);

    unsigned char* last_message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), last_message_received);
    if( ret == 0) {
        cout << RED  << "** server disconnected **" << RESET << endl;
        free(last_message_received);
        return false;
    }  

    char opCode;
    byte_index = 0;    
    int signature_size = 0;
    
    memcpy(&(opCode), &last_message_received[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(nonceClient.data(), &last_message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(nonceServer, &last_message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    cout << "Nonce: " << endl;
    for(int i = 0; i < constants::NONCE_SIZE; i++) {
        cout << nonceClient_t[i];
    }

    cout << " | ";

    for(int i = 0; i < constants::NONCE_SIZE; i++) {
        cout << nonceClient.data()[i];
    }
    cout << endl;
    cout << endl;

    if(memcmp(nonceClient_t, nonceClient.data(), constants::NONCE_SIZE) != 0){
        cerr << "2) Nonce received is not valid!";
        exit(1);
    } else {
        cout << GREEN << "** Nonce verified **" << RESET << endl;
    }

    memcpy(&(pubKeyDHBufferLen), &last_message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    memcpy(pubKeyDHBuffer.data(), &last_message_received[byte_index], pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;
    
   // delete the plaintext from memory:
#pragma optimize("", off)
   memset(clear_buf, 0, dim);
#pragma optimize("", on)

    free(clear_buf);
    free(clear_buf);
    free(signature);

    clt.crypto->deserializePublicKey(pubKeyDHBuffer.data(), pubKeyDHBufferLen, pubKeyDHServer);

    dim = byte_index;
    byte_index = 0;
    
    clear_buf = (unsigned char*)malloc(dim);
    memcpy(clear_buf, &last_message_received[byte_index], dim);
    byte_index += dim;

    sign_size = 0;
    memcpy(&sign_size, &last_message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    signature = (unsigned char*)malloc(sign_size);
    memcpy(signature, &last_message_received[byte_index], sign_size);
    byte_index += sign_size;
    
    verify = clt.crypto->digsign_verify(signature, sign_size, clear_buf, sizeof(int), pubKeyServer);
    if(verify < 0) {
        cerr << "Invalid signature!" << endl;
        return false;
    } else {
        cout << GREEN << "** valid signature **" << RESET << endl;
    }

    cout << GREEN << "*** Generating session key ***" << RESET << endl;

    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    clt.crypto->secretDerivation(prvKeyDHClient, pubKeyDHServer, tempBuffer.data());
    clt.clientConn->addSessionKey(tempBuffer.data(), tempBuffer.size());

    cout << YELLOW << "*** Authentication succeeded ***" << RESET << endl;

#pragma optimize("", off)
    memset(clear_buf, 0, dim);
    memset(tempBuffer.data(), 0, tempBuffer.size());
#pragma optimize("", on)

    free(message_sent);
    free(message_received);
    free(nonceServer);
    free(nonceClient_rec);
    free(nonceClient_t);

    return true;
}

bool receiveRequestToTalk(Client &clt, char* msg) {

    unsigned int tempBufferLen = 0;
    unsigned int keyBufferLen = 0;
    unsigned int keyBufferDHLen = 0;
    EVP_PKEY *keyDH = NULL;
    EVP_PKEY *peerKeyDH = NULL;
    EVP_PKEY *peerPubKey = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> keyDHBuffer;

    bool verify = false;

    int byte_index = 0;
    unsigned char* username = NULL;
    unsigned int username_size = 0;
    unsigned char* response_to_request = NULL;
    unsigned char response = 'n';
    int dim = 0;

    byte_index += sizeof(char);

    memcpy(&(username_size), &msg[byte_index], sizeof(int));
    byte_index += sizeof(int);

    if(username_size < 0 || username_size > constants::MAX_MESSAGE_SIZE) {
        cerr << "Username size error!" << endl;
        return false;
    }

    username = (unsigned char*)malloc(username_size);
    if(username == NULL) {
        cerr << "Username malloc error!" << endl;
        return false;
    }

    memcpy(username, &msg[byte_index], username_size);
    byte_index += username_size;

    if(memcpy((void*)clt.username.c_str(), username, username_size) == 0) {
        cout << RED << "You're trying to speak with yourself, insert a valid username" << RESET << endl;
        return false;
    }
   
    cout << "Do you want to talk with ";
    for(unsigned int i = 0; i < username_size; i++) {
        cout << username[i];
    }

    cout << "? (y/n)" << endl;

    cin >> response;
    cin.ignore();

    // Messaggio con chiave pubblica DH
    if(response == 'y') {
        cout << GREEN << "ok so i'll start the chat" << RESET << endl;


        clt.crypto->keyGeneration(keyDH);
        keyBufferDHLen = clt.crypto->serializePublicKey(keyDH, keyDHBuffer.data());
        dim = sizeof(char) + sizeof(int) + keyBufferDHLen;
        response_to_request = (unsigned char*)malloc(dim); 
        if(response_to_request == NULL) {
            cerr << "Malloc response error!" << endl;
            return false;
        }
        byte_index = 0;
        memcpy(&(response_to_request[byte_index]), &constants::ACCEPTED, sizeof(char));
        byte_index += sizeof(char);

        memcpy(&(response_to_request[byte_index]), &keyBufferDHLen, sizeof(int));
        byte_index += sizeof(int);

        memcpy(&(response_to_request[byte_index]), keyDHBuffer.data(), keyBufferDHLen);
        byte_index += keyBufferDHLen;

    cout << "***********************************" << endl;
        
    } 
    else {
        cout << RED << ":(" << RESET << endl;

        dim = sizeof(char);

        response_to_request = (unsigned char*)malloc(dim); 
        if(response_to_request == NULL) {
            cerr << "Malloc response error!" << endl;
            return false;
        }
        byte_index = 0;
        memcpy(&(response_to_request[byte_index]), &constants::REFUSED, sizeof(char));
        byte_index += sizeof(char);
    }  

    //Messaggio con errore
        
    /*memcpy(response_to_request, &response, sizeof(char));
    byte_index += sizeof(char);*/

    clt.clientConn->send_message(response_to_request, dim);

    free(response_to_request);
    free(username);
    return true;
}

void start_chat(Client clt, string username, string username_to_contact) {

    int dim = username.size() + username_to_contact.size() + sizeof(char) + sizeof(int) + sizeof(int);

    unsigned char* buffer = (unsigned char*)malloc(dim);
    int byte_index = 0;   

    memcpy(&(buffer[byte_index]), &constants::START_CHAT, sizeof(char));
    byte_index += sizeof(char);

    int username_1_size = username.size();
    memcpy(&(buffer[byte_index]), &username_1_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(buffer[byte_index]), username.c_str(), username.size());
    byte_index += username.size();

    int username_2_size = username_to_contact.size();
    memcpy(&(buffer[byte_index]), &username_2_size, sizeof(int));
    byte_index += sizeof(int);
    
    memcpy(&(buffer[byte_index]), username_to_contact.c_str(), username_to_contact.size());
    byte_index += username_to_contact.size();

    clt.clientConn->send_message(buffer,dim);
}

void chat(Client clt) {
    fd_set fds;
    string message;
    unsigned char* buffer = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    unsigned char* to_send;
    int maxfd;

    int ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
    if (ret == 0) {
        cout << RED << "** client connection closed **" << RESET << endl;
        free(buffer);
        return;
    } 

    int username_size = 0;
    int byte_index = 0;

    memcpy(&(username_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* username_talking_to = (unsigned char*)malloc(username_size);
    if(!username_talking_to) {
        throw runtime_error("malloc failed");
    }

    memcpy(username_talking_to, &buffer[byte_index], username_size);
    byte_index += username_size;

    cout << "Talking to ";

    for(int i = 0; i < username_size; i++) {
        cout << username_talking_to[i];
    }
    cout << endl;

    clt.clientConn->setTalkingTo(username_talking_to);

    buffer = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);

    while(1) {

        memset(buffer, 0, constants::MAX_MESSAGE_SIZE);

        maxfd = (clt.clientConn->getMasterFD() > STDIN_FILENO) ? clt.clientConn->getMasterFD() : STDIN_FILENO;
        FD_ZERO(&fds);
        FD_SET(clt.clientConn->getMasterFD(), &fds); 
        FD_SET(STDIN_FILENO, &fds); 
        
        select(maxfd+1, &fds, NULL, NULL, NULL); 

        if(FD_ISSET(0, &fds)) {  
            cout << "\n ";
            getline(cin, message);
            cout << endl;

            if(message.compare(":q!") == 0) {
                break;
            }

            int byte_index = 0;
            int dim_send = sizeof(char) + sizeof(int) + message.size();
            to_send = (unsigned char*)malloc(dim_send);

            memcpy(&(to_send[byte_index]), &(constants::CHAT), sizeof(char));
            byte_index += sizeof(char);

            int message_size = message.size();
            memcpy(&(to_send[byte_index]), &message_size , sizeof(int));
            byte_index += sizeof(int);

            memcpy(&(to_send[byte_index]), message.c_str(), message_size);
            byte_index += message_size;

            clt.clientConn->send_message(to_send, message_size);

        }

        if(FD_ISSET(clt.clientConn->getMasterFD(), &fds)) {
            ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), buffer);
            if (ret == 0) {
                cout << RED << "**client connection closed**" << RESET << endl;
                free(buffer);
                return;
            } 

            cout << "message_size: " << ret << endl;

            int size_received = 0;
            memcpy(&size_received, buffer + sizeof(char), sizeof(int));

            cout << "encrypted_size: " << size_received << endl;

            vector<unsigned char> message_decrypted;
            int decrypted_size = clt.crypto->decryptMessage(clt.clientConn->getSessionKey(),clt.clientConn->getIV(), buffer, size_received, message_decrypted);

            //cout << "decrypted_size: " << decrypted_size << endl;

            cout << "message_decrypted: " << endl;
            for(int i = 0; i < constants::MAX_MESSAGE_SIZE; i++) {
                cout << message_decrypted[i];
            }

            cout << endl;

            int message_size = 0;
            int byte_index = sizeof(char);

            unsigned char* message;

            memcpy(&(message_size), &buffer[byte_index], sizeof(int));
            byte_index += sizeof(int);

            message = (unsigned char*)malloc(sizeof(char) + sizeof(int) + message_size);
            
            memcpy(message, &buffer[byte_index], message_size);
            byte_index += message_size;

            for(int i = 0; i < username_size; i++) {
                cout << username_talking_to[i];
            }
            cout << ": ";

            for(int i = 0; i < message_size; i++) {
                cout << message[i];
            }

            cout << endl;
        }
    }
    
}

void sendRequestToTalk(Client clt, string username_to_contact, string username) {
    int byte_index = 0;  
    int peerPubKeyLen = 0;
    int peerKeyDHLen = 0;
    unsigned char* peerKeyDHBuffer;
    unsigned char* peerPubKeyBuffer;  
    EVP_PKEY *peerKeyDH = NULL;
    EVP_PKEY *peerPubKey = NULL;
    EVP_PKEY *sessionDHKey = NULL;
    EVP_PKEY *keyDH = NULL;
    unsigned char* keyDHBuffer = NULL;
    int keyDHBufferLen = 0;
    vector<unsigned char> encrypted;

    // OPCODE | sizeof(username) | username
    int dim = sizeof(char) + sizeof(int) + username_to_contact.size();
    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::REQUEST, sizeof(char));
    byte_index += sizeof(char);

    int username_to_contact_size = username_to_contact.size();
    memcpy(&(message[byte_index]), &username_to_contact_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), username_to_contact.c_str(), username_to_contact.size());
    byte_index += username_to_contact.size();

    send_message_enc(clt.clientConn->getMasterFD(), clt, message, dim, encrypted);

    // clt.clientConn->send_message(message, dim);

    unsigned char* response = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);  

    cout << "** waiting for response ** " << endl;

    int ret = clt.clientConn->receive_message(clt.clientConn->getMasterFD(), response);
    if (ret == 0) {
        cout << RED << "client connection closed" << RESET << endl;
        free(response);
        return;
    } 

    // Cambiare controllo con l'opcode corretto
    
    if(response[0] == constants::ACCEPTED) {
        cout << GREEN << "request accepted, starting the chat" << RESET << endl;
        cout << "---------------------------------------" << endl;
        cout << "\n-------Chat-------" << endl;

        //clt.clientConn->chat->peer_username = (unsigned char*)username_to_contact.c_str();

        byte_index = 0;

        byte_index += sizeof(char);

        memcpy(&(peerKeyDHLen), &response[byte_index], sizeof(int));
        byte_index += sizeof(int);

        peerKeyDHBuffer = (unsigned char*)malloc(peerKeyDHLen);
        if(!peerKeyDHBuffer) {
            throw runtime_error("malloc failed");
        }

        memcpy(peerKeyDHBuffer, &response[byte_index], peerKeyDHLen);
        byte_index += peerKeyDHLen;

        clt.crypto->deserializePublicKey(peerKeyDHBuffer, peerKeyDHLen, peerKeyDH);

        memcpy(&(peerPubKeyLen), &response[byte_index], sizeof(int));
        byte_index += sizeof(int);

        peerPubKeyBuffer = (unsigned char*)malloc(peerPubKeyLen);
        if(!peerPubKeyBuffer) {
            throw runtime_error("malloc failed");
        }

        memcpy(peerPubKeyBuffer, &response[byte_index], peerPubKeyLen);
        byte_index += peerPubKeyLen;

        clt.crypto->deserializePublicKey(peerPubKeyBuffer, peerPubKeyLen, clt.clientConn->getCurrentChat()->pubkey_1);

        //Costruire chiave di sessione prvDH

        cout << GREEN << "*** Generating session key ***" << RESET << endl;

        array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
        clt.crypto->secretDerivation(sessionDHKey, peerKeyDH, tempBuffer.data());
        //Perchè così serializzata?!
        userChat* currentChat = clt.clientConn->getCurrentChat();
        if(!clt.clientConn->getCurrentChat()->session_key) {
            throw runtime_error("malloc failed");
        }
        // memcpy(clt.clientConn->chat->session_key, tempBuffer.data(), tempBuffer.size());

        cout << YELLOW << "*** Authentication succeeded ***" << RESET << endl;

        //Costruire e inviare mia chiave DH

        // opcode | keyDHlen | keyDH

        clt.crypto->keyGeneration(keyDH);
        keyDHBufferLen = clt.crypto->serializePublicKey(keyDH, keyDHBuffer);
        dim = sizeof(char) + sizeof(int) + keyDHBufferLen;
        free(message);
        
        message = (unsigned char*)malloc(dim); 
        if(message == NULL) {
            throw runtime_error("Malloc error");
        }
        byte_index = 0;
        memcpy(&(message[byte_index]), &constants::ACCEPTED, sizeof(char));
        byte_index += sizeof(char);

        memcpy(&(message[byte_index]), &keyDHBufferLen, sizeof(int));
        byte_index += sizeof(int);

        memcpy(&(message[byte_index]), keyDHBuffer, keyDHBufferLen);
        byte_index += keyDHBufferLen;


        //Inviare messaggio


        //Quando abbiamo finito togliere start_chat, per ora lo lascio per le prove
        start_chat(clt, username, username_to_contact);

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

    memcpy(&(message[byte_index]), &constants::LOGOUT, sizeof(char));
    byte_index += sizeof(char);
    clt.clientConn->send_message(message, dim);
}

void seeOnlineUsers(Client clt, vector<unsigned char> &buffer){

    int byte_index = 0;    

    int dim = sizeof(char);
    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::ONLINE, sizeof(char));
    byte_index += sizeof(char);
    
    clt.clientConn->send_message(message, dim);

    free(message);
    buffer.clear();
    unsigned char* message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);  

    clt.clientConn->generateIV();
    int ret = receive_message_enc(clt, message_received, buffer);

    if (ret == 0) {
        cout << RED << "client connection closed" << RESET << endl;
        buffer.clear();
        return;
    } else {
        cout << GREEN << "list received" << RESET << endl;
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

    if(list_size == 0) {
        cout << RED << "--- no user online ---" <<  endl;
    } else {
        cout << "--- online users ---" << endl;

        cout << GREEN << " | ";

        for(int i = 0; i < list_size; i++) {
            int username_size = 0;

            memcpy(&(username_size), &buffer[byte_index], sizeof(int));
            byte_index += sizeof(int);

            unsigned char* username = (unsigned char*)malloc(username_size);
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

