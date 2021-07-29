#include <limits>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <iostream>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>   
#include <sys/time.h> 
#include <errno.h>
#include <time.h>      
#include "constants.h"
#include "client.h"
#include "color.h"

using namespace std;

struct Server {
    serverConnection *serverConn;
    CryptoOperation *crypto;

    Server() {
        serverConn = new serverConnection();
        crypto = new CryptoOperation();
    }
};

bool authentication(Server &srv, int sd, unsigned char* buffer) {
    array<unsigned char, NONCE_SIZE> nonceServer;
    unsigned char* nonceServer_rec= (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* nonceServer_t = (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* nonceClient = (unsigned char*)malloc(constants::NONCE_SIZE);

    unsigned char* cert_buf = NULL;
    X509 *cert;
    EVP_PKEY* prvkey_server;
    unsigned int pubKeyDHBufferLen;
    EVP_PKEY *prvKeyDHServer = NULL;
    EVP_PKEY *pubKeyDHClient = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;

    int byte_index = 0;    
    char opCode;
    unsigned char* username;
    unsigned char* signature;
    int username_size = 0;
    int signature_size = 0;
        
    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(username_size), &buffer[byte_index],sizeof(int));
    byte_index += sizeof(int);

    username = (unsigned char*)malloc(username_size);
    memcpy(username, &buffer[byte_index], username_size);
    byte_index += username_size;

    memcpy(nonceClient, &buffer[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(signature_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    signature = (unsigned char*)malloc(signature_size);
    memcpy(signature, &buffer[byte_index], signature_size);
    byte_index += signature_size;

    std::stringstream filename_stream;
    std::stringstream username_string;

    for(int i = 0; i < username_size; i++) {
        filename_stream << username[i];
        username_string << username[i];
    }

    cout << endl;

    filename_stream << "_pubkey.pem";

    string filename = filename_stream.str();

    string filename_dir = "keys/public/" + filename;
        
    FILE* file;
    file = fopen(filename_dir.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");

    EVP_PKEY *pubkey_server = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubkey_server){
        fclose(file);
        throw runtime_error("An error occurred while reading the public key.");
    }

    byte_index = 0;
    int dim = sizeof(char) + sizeof(int) + username_size + constants::NONCE_SIZE; 
    unsigned char* clear_buf = (unsigned char*)malloc(dim);

    memcpy(clear_buf, &buffer[byte_index], dim);
    byte_index += sizeof(char);

    int sign_size = 0;
    memcpy(&sign_size, &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* sign = (unsigned char*)malloc(sign_size);
    memcpy(sign, &buffer[byte_index], sign_size);
    byte_index += sign_size;
    
    unsigned int verify = srv.crypto->digsign_verify(sign, sign_size, clear_buf, sizeof(int), pubkey_server);
    if(verify < 0) {
        cerr << "establishSession: invalid signature!";
        return false;
    } else {
        cout << GREEN << "** valid signature **" << RESET << endl;
    }
    
    srv.serverConn->insertUser(username_string.str(), sd);
    srv.serverConn->printOnlineUsers();
	
	srv.crypto->readPrivateKey("srv", "cybersecurity", prvkey_server);
	if(!prvkey_server) {
        cerr << "establishSession: server_key Error";
        exit(1);
    }
	fclose(file);

    srv.crypto->generateNonce(nonceServer.data());
    nonceServer_t = nonceServer.data();

    srv.crypto->loadCertificate(cert, "server_cert");

    int cert_size = i2d_X509(cert, &cert_buf);        
    if(cert_size < 0) { 
        throw runtime_error("An error occurred during the reading of the certificate."); 
    }

    byte_index = 0;    
    dim = sizeof(char) + sizeof(int) + cert_size + constants::NONCE_SIZE + constants::NONCE_SIZE;
    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &cert_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), cert_buf, cert_size);
    byte_index += cert_size;

    memcpy(&(message[byte_index]), nonceServer.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    
    memcpy(&(message[byte_index]), nonceClient, constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    
    unsigned char* message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    unsigned int signed_size = srv.crypto->digsign_sign(message, dim, message_signed, prvkey_server);

    srv.serverConn->send_message(message, sd, dim);

    unsigned char* message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    int ret = srv.serverConn->receive_message(sd, message_received);
    if( ret == 0) {
        cout << RED  << "** client disconnected **" << RESET << endl;
        free(message_received);
        return true;
    }  

    byte_index = 0;    
    signature_size = 0;
    
    memcpy(&(opCode), &message_received[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(nonceClient, &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(nonceServer_rec, &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    if(memcmp(nonceServer_t, nonceServer_rec, constants::NONCE_SIZE) != 0){
        cerr << "Nonce received is not valid!";
        exit(1);
    } else {
        cout << GREEN << "** Nonce verified **" << RESET << endl;
    }

    memcpy(&(pubKeyDHBufferLen), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    memcpy(pubKeyDHBuffer.data(), &message_received[byte_index], pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;

    dim = byte_index;

    srv.crypto->deserializePublicKey(pubKeyDHBuffer.data(), pubKeyDHBufferLen, pubKeyDHClient);
    srv.crypto->keyGeneration(prvKeyDHServer);

    free(clear_buf);
    free(signature);
    
    clear_buf = (unsigned char*)malloc(dim);
    byte_index = 0;
    signature = 0;

    memcpy(clear_buf, &message_received[byte_index], dim);
    byte_index += dim;

    memcpy(&(signature_size), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    signature = (unsigned char*)malloc(signature_size);
    memcpy(signature, &message_received[byte_index], signature_size);
    byte_index += signature_size;

    // verificare firma con chieve pubblica del client
    verify = srv.crypto->digsign_verify(signature, signature_size, clear_buf, sizeof(int), pubkey_server);
    if(verify < 0){
        cerr << "establishSession: invalid signature!"; 
        return false;
    } else {
        cout << GREEN << "** Valid Signature **" << RESET << endl;
    }

    // ultimo messaggio di autenticazione: 
    // OPCODE | nonceClient | nonceServer | pubkeyDHServer_len | pubkeyDHServer | DIGSIGN

    pubKeyDHBufferLen = srv.crypto->serializePublicKey(prvKeyDHServer, pubKeyDHBuffer.data());
    
    srv.crypto->generateNonce(nonceServer.data());
    nonceServer_t = nonceServer.data();

    byte_index = 0;    
    dim = sizeof(char) + 2*constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferLen;
    unsigned char* last_message = (unsigned char*)malloc(dim);  

    memcpy(&(last_message[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(last_message[byte_index]), nonceServer.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    
    memcpy(&(last_message[byte_index]), nonceClient, constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(last_message[byte_index]), &pubKeyDHBufferLen, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(last_message[byte_index]), pubKeyDHBuffer.data(), pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;
    
    unsigned char* last_message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    signed_size = srv.crypto->digsign_sign(last_message, dim, last_message_signed, prvkey_server);

    cout << MAGENTA << "dim: " << dim << RESET << endl;

    cout << MAGENTA << "signed_size: " << signed_size << RESET << endl;

    srv.serverConn->send_message(last_message_signed, sd, signed_size);

    // Generate secret
    cout << GREEN << "*** Generating session key ***" << RESET << endl;

    unsigned char* temp_session_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    srv.crypto->secretDerivation(prvKeyDHServer, pubKeyDHClient, temp_session_key);

    srv.serverConn->addSessionKey(sd, temp_session_key);
    
    cout << YELLOW << "*** Authentication succeeded ***" << RESET << endl;

    free(temp_session_key);
    free(nonceClient);
    free(username);
    return true;   
}

int decrypt_message(Server srv, int sd, unsigned char* message, int dim, vector<unsigned char> &decrypted) {

    cout << MAGENTA << "[DEBUG] " << "decrypting" << RESET << endl;

    unsigned char* message_decrypted = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    int decrypted_size = srv.crypto->decryptMessage(srv.serverConn->getSessionKey(sd), srv.serverConn->getIV(), message, dim, decrypted);

    cout << MAGENTA << "[DEBUG] " << "decrypted" << RESET << endl;

    return decrypted_size;
}

int send_message_enc_srv(CryptoOperation* crypto, int fd, unsigned char* key, unsigned char* iv, unsigned char* message, int dim, vector<unsigned char> &encrypted) {
    int ret = 0;

    printf("plaintext is:\n");
    BIO_dump_fp(stdout, (const char*)message, dim);

    printf("key is:\n");
    BIO_dump_fp(stdout, (const char*)key, sizeof(key));

    printf("iv is:\n");
    BIO_dump_fp(stdout, (const char*)iv, constants::IV_LEN);

    int encrypted_size = crypto->encryptMessage(key, iv, message, dim, encrypted);

    printf("ciphertext to send is:\n");
    BIO_dump_fp(stdout, (const char*)encrypted.data(), encrypted_size);

    do {
        ret = send(fd, encrypted.data(), encrypted_size, 0);
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

bool seeOnlineUsers(Server &srv, int sd, vector<unsigned char> &buffer) {

    int byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + sizeof(int);
    vector<user> users_logged_in = srv.serverConn->getUsersList();
    unsigned char* message;
    buffer.clear();

    for(size_t i = 0; i < users_logged_in.size(); i++) {
        cout << CYAN << "user " << users_logged_in[i].username << RESET << endl;
        dim += users_logged_in[i].username.size();
        dim += sizeof(int);
    }

    message = (unsigned char*)malloc(dim);

    memcpy(&(message[byte_index]), &constants::ONLINE, sizeof(char));
    byte_index += sizeof(char);

    int dim_message = 0;

    for(size_t i = 0; i < users_logged_in.size(); i++) {
        dim_message += sizeof(int);
        dim_message += users_logged_in[i].username.size();
    }   

    cout << "dim_message" << dim_message << endl;
    memcpy(&(message[byte_index]), &dim_message, sizeof(int));
    byte_index += sizeof(int);

    int list_size = users_logged_in.size();
    cout << "list_size: " << list_size << endl;
    memcpy(&(message[byte_index]), &list_size, sizeof(int));
    byte_index += sizeof(int);

    for(size_t i = 0; i < users_logged_in.size(); i++) {

        int username_size = users_logged_in[i].username.size();

        memcpy(&(message[byte_index]), &username_size, sizeof(int));
        byte_index += sizeof(int);

        memcpy(&(message[byte_index]), users_logged_in[i].username.c_str(), users_logged_in[i].username.size());
        byte_index += users_logged_in[i].username.size();
    }   

    printf("sending encrypted is:\n");
    BIO_dump_fp(stdout, (const char*)message, dim);

    srv.serverConn->generateIV();
    send_message_enc_srv(srv.crypto, sd, srv.serverConn->getSessionKey(sd), srv.serverConn->getIV(), message, byte_index, buffer);

    return true;   
}

bool requestToTalk(Server &srv, int sd, unsigned char* buffer) {

    int byte_index = 0;    
    char opCode;
    int username_to_talk_to_size = 0;
    int username_size = 0;
    vector<user> users_logged_in = srv.serverConn->getUsersList();

    memcpy(&opCode, &(buffer[byte_index]), sizeof(char));
    byte_index += sizeof(char);

    memcpy(&username_to_talk_to_size, &(buffer[byte_index]), sizeof(int));
    byte_index += sizeof(int);

    unsigned char* username_to_talk_to = (unsigned char*)malloc(username_to_talk_to_size);

    memcpy(username_to_talk_to, &(buffer[byte_index]), username_to_talk_to_size);
    byte_index += username_to_talk_to_size;

    memcpy(&username_size, &(buffer[byte_index]), sizeof(int));
    byte_index += sizeof(int);

    unsigned char* username = (unsigned char*)malloc(username_size);

    memcpy(username, &(buffer[byte_index]), username_size);
    byte_index += username_size;

    cout << CYAN << "so ";
    for(int i = 0; i < username_size; i++){
        cout << username[i];
    }
    cout << " want to talk with ";
    for(int i = 0; i < username_to_talk_to_size; i++){
        cout << username_to_talk_to[i];
    }
    cout << RESET << endl;

    for(auto us : srv.serverConn->getActiveChats()) {
        if(memcmp(us->username_1, username, username_size) == 0 || 
            memcmp(us->username_2, username, username_size) == 0) 
            {
                cout << RED << "user already chatting.." << RESET << endl;
                free(username_to_talk_to);
                free(username);

                unsigned char* already_chatting = (unsigned char*)malloc(sizeof(char));
                already_chatting[0] = 'n';

                srv.serverConn->send_message(already_chatting, sd, sizeof(char));

                free(already_chatting);
                return true;
            }

        if(memcmp(us->username_1, username_to_talk_to, username_to_talk_to_size) == 0 || 
            memcmp(us->username_2, username_to_talk_to, username_to_talk_to_size) == 0) 
            {
                cout << RED << "user already chatting.." << RESET << endl;
                free(username_to_talk_to);
                free(username);

                unsigned char* already_chatting = (unsigned char*)malloc(sizeof(char));
                already_chatting[0] = 'n';

                srv.serverConn->send_message(already_chatting, sd, sizeof(char));

                free(already_chatting);
                return true;
            }
    }

    byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + username_size;
    unsigned char* message = (unsigned char*)malloc(dim);  

    memcpy(&(message[byte_index]), &constants::FORWARD, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &username_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), username, username_size);
    byte_index += username_size;

    int user_to_talk_to_sd = 0;
    for(size_t i = 0; i < users_logged_in.size(); i++) {
        if(strncmp(users_logged_in[i].username.c_str(), reinterpret_cast<const char*>(username_to_talk_to), username_size) == 0) {
            srv.serverConn->send_message(message,users_logged_in[i].sd, dim);
            user_to_talk_to_sd = users_logged_in[i].sd;
        }
    }

    unsigned char* response = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);

    int ret = srv.serverConn->receive_message(user_to_talk_to_sd, response);
    if(ret == 0) {
        cout << RED <<"**client disconnected**" << RESET << endl;
        return false;
    }

    srv.serverConn->send_message(response, sd, dim);

    free(username_to_talk_to);
    free(username);
    free(response);
    return true;       
}

bool start_chat(Server srv, int sd, unsigned char* buffer) {
    char opCode;
    int byte_index = 0;
    unsigned char* username_1;
    unsigned char* username_2;
    int username_1_size = 0;

    int username_2_size = 0;

    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(username_1_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    username_1 = (unsigned char*)malloc(username_1_size);
    memcpy(username_1, &buffer[byte_index], username_1_size);
    byte_index += username_1_size;

    memcpy(&(username_2_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    username_2 = (unsigned char*)malloc(username_2_size);
    memcpy(username_2, &buffer[byte_index], username_2_size);
    byte_index += username_2_size;

    int sd_1 = 0;
    int sd_2 = 0;

    vector<user> users_logged_in = srv.serverConn->getUsersList();
    for(auto user : users_logged_in) {
        if(memcmp(user.username.c_str(), username_1, username_1_size) == 0) {
            sd_1 = user.sd;
        }

        if(memcmp(user.username.c_str(), username_2, username_2_size) == 0) {
            sd_2 = user.sd;
        }
    }

    userChat *new_chat = new userChat(username_1, sd_1, username_2, sd_2);
    srv.serverConn->insertChat(new_chat);

    byte_index = 0;

    int dim_m1 = username_2_size + sizeof(int);
    unsigned char* m1 = (unsigned char*)malloc(dim_m1);

    memcpy(&(m1[byte_index]), &username_2_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(m1[byte_index]), username_2, username_2_size);
    byte_index += username_2_size;

    srv.serverConn->send_message(m1, sd_1, dim_m1);

    byte_index = 0;

    int dim_m2 = username_2_size + sizeof(int);
    unsigned char* m2 = (unsigned char*) malloc(dim_m2);

    memcpy(&(m2[byte_index]), &username_1_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(m2[byte_index]), username_1, username_1_size);
    byte_index += username_1_size;

    srv.serverConn->send_message(m2, sd_2, dim_m2);

    return true;
}

bool chatting(Server srv, int sd, unsigned char* buffer) {

    unsigned char* message_received;
    unsigned char recv_iv[constants::IV_LEN];
    unsigned char recv_tag[constants::TAG_LEN];
    int message_size = 0;
    int byte_index = 0;
    int sd_to_send = -1;
    char opCode;

    sd_to_send = srv.serverConn->findSd(sd);

    if(sd_to_send == -1) {
        cout << RED << "**no chat found**" << RESET << endl;
        return false;
    }

    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    cout << MAGENTA << "[DEBUG] " << "opcode: " << opCode << RESET << endl; 

    memcpy(&(message_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    cout << MAGENTA << "[DEBUG] " << "message_size: " << message_size << RESET << endl; 

    message_received = (unsigned char*)malloc(message_size);
    memcpy(message_received, &buffer[byte_index], message_size);
    byte_index += message_size;

    /*
    memcpy(recv_iv, &buffer[byte_index], constants::IV_LEN);
    byte_index += constants::IV_LEN;
    memcpy(recv_tag, &buffer[byte_index], constants::TAG_LEN);
    byte_index += constants::TAG_LEN;
    */

    srv.serverConn->send_message(buffer, sd_to_send, byte_index);

    free(message_received);
    return true;   
}

