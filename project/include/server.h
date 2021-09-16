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
    array<unsigned char, constants::NONCE_SIZE> nonceServer;
    array<unsigned char, constants::NONCE_SIZE> nonceServer_rec;
    array<unsigned char, constants::NONCE_SIZE> nonceServer_t;
    array<unsigned char, constants::NONCE_SIZE> nonceClient;
    array<unsigned char, constants::MAX_MESSAGE_SIZE> pubKeyDHBuffer;

    unsigned char* cert_buf = NULL;
    X509 *cert = NULL;
    EVP_PKEY* prvkey_server = NULL;
    unsigned int pubKeyDHBufferLen = 0;
    EVP_PKEY *prvKeyDHServer = NULL;
    EVP_PKEY *pubKeyDHClient = NULL;
    int byte_index = 0;    
    char opCode;
    unsigned char* username = NULL;
    unsigned char* signature = NULL;
    int username_size = 0;
    int signature_size = 0;
        
    memcpy(&(opCode), &buffer[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(username_size), &buffer[byte_index],sizeof(int));
    byte_index += sizeof(int);

    username = (unsigned char*)malloc(username_size);
    if(!username) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(username, &buffer[byte_index], username_size);
    byte_index += username_size;

    vector<user> already_logged_in = srv.serverConn->getUsersList();

    if(already_logged_in.size() != 0) {
        int already_logged_error = 1;


        for(auto us : already_logged_in) {

            if(us.username.size() == username_size) {

                already_logged_error = 1;

                for(int i = 0; i < username_size; i++) {
                    if(us.username.c_str()[i] != username[i]) {
                        already_logged_error = 0;
                        break;
                    }
                }

                if(already_logged_error == 1) {
                    break;
                } 
            } else {
                already_logged_error = 0;
            }
        }

        if(already_logged_error == 1) {
            free(username);
            
            unsigned char* error_message = (unsigned char*)malloc(sizeof(char));
            memcpy(error_message, &constants::ERROR_CODE, sizeof(char));

            srv.serverConn->send_message(error_message, sd, sizeof(char));

            return true;
        }
    }

    memcpy(nonceClient.data(), &buffer[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(signature_size), &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    signature = (unsigned char*)malloc(signature_size);
    if(!signature) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

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
    if(!file) {
        cerr << RED << "[ERROR] File does not exist!" << RESET << endl;
        return false;
    }

    EVP_PKEY *pubkey_client = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubkey_client){
        fclose(file);
        cerr << RED << "[ERROR] Public key error!" << RESET << endl;
        return false;
    }

    byte_index = 0;
    int dim = sizeof(char) + sizeof(int) + username_size + constants::NONCE_SIZE; 
    unsigned char* clear_buf = (unsigned char*)malloc(dim);
    if(!clear_buf) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(clear_buf, &buffer[byte_index], dim);
    byte_index += sizeof(char);

    int sign_size = 0;
    memcpy(&sign_size, &buffer[byte_index], sizeof(int));
    byte_index += sizeof(int);

    unsigned char* sign = (unsigned char*)malloc(sign_size);
    if(!sign) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(sign, &buffer[byte_index], sign_size);
    byte_index += sign_size;
    
    unsigned int verify = srv.crypto->digsign_verify(sign, sign_size, clear_buf, sizeof(int), pubkey_client);
    if(verify < 0) {
        cerr << RED << "[ERROR] invalid signature!" << RESET << endl;
        return false;
    } else {
        cout << GREEN << "[LOG] valid signature " << RESET << endl;
    }
    
    srv.serverConn->insertUser(username_string.str(), sd);
    srv.serverConn->printOnlineUsers();
	
	srv.crypto->readPrivateKey("srv", "cybersecurity", prvkey_server);
	if(!prvkey_server) {
        cerr << RED << "[ERROR] server_key Error" << RESET << endl;
        exit(1);
    }
	fclose(file);

    srv.crypto->generateNonce(nonceServer.data());
    memcpy(nonceServer_t.data(), nonceServer.data(), nonceServer.size());

    srv.crypto->loadCertificate(cert, "server_cert");

    int cert_size = i2d_X509(cert, &cert_buf);        
    if(cert_size < 0) { 
        cerr << RED << "[ERROR] Error reading the certificate" << RESET << endl;
        return false;
    }

    byte_index = 0;    
    dim = sizeof(char) + sizeof(int) + cert_size + constants::NONCE_SIZE + constants::NONCE_SIZE;
    unsigned char* message = (unsigned char*)malloc(dim);  
    if(!message) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(&(message[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &cert_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), cert_buf, cert_size);
    byte_index += cert_size;

    memcpy(&(message[byte_index]), nonceServer.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    
    memcpy(&(message[byte_index]), nonceClient.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    
    unsigned char* message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    if(!message_signed) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    unsigned int signed_size = srv.crypto->digsign_sign(message, dim, message_signed, prvkey_server);
    if(signed_size < 0) {
        cerr << RED << "[ERROR] invalid signature!" << RESET << endl;
        return false;
    } else {
        cout << GREEN << "[LOG] valid signature " << RESET << endl;
    }

    int ret = srv.serverConn->send_message(message, sd, dim);
    if( ret <= 0) {
        cout << RED  << "[LOG] client disconnected " << RESET << endl;
        free(message);
        return true;
    } 

    unsigned char* message_received = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
    if(!message_signed) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    ret = srv.serverConn->receive_message(sd, message_received);
    if( ret <= 0) {
        cout << RED  << "[LOG] client disconnected " << RESET << endl;
        free(message_received);
        return true;
    }  

    byte_index = 0;    
    signature_size = 0;
    
    memcpy(&(opCode), &message_received[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(nonceClient.data(), &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(nonceServer_rec.data(), &message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    if(memcmp(nonceServer_t.data(), nonceServer_rec.data(), constants::NONCE_SIZE) != 0){
        cerr << RED << "[ERROR] Nonce received is not valid" << RESET << endl;
        exit(1);
    } else {
        cout << GREEN << "[LOG] Nonce verified " << RESET << endl;
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
    if(!clear_buf) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    byte_index = 0;
    signature = 0;

    memcpy(clear_buf, &message_received[byte_index], dim);
    byte_index += dim;

    memcpy(&(signature_size), &message_received[byte_index], sizeof(int));
    byte_index += sizeof(int);

    signature = (unsigned char*)malloc(signature_size);
    if(!signature) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(signature, &message_received[byte_index], signature_size);
    byte_index += signature_size;

    // verificare firma con chieve pubblica del client
    verify = srv.crypto->digsign_verify(signature, signature_size, clear_buf, sizeof(int), pubkey_client);
    if(verify < 0){
        cerr << RED << "[ERROR] Signature is not valid" << RESET << endl;
        exit(1);
    } else {
        cout << GREEN << "[LOG] Valid Signature " << RESET << endl;
    }

    // ultimo messaggio di autenticazione: 
    // OPCODE | nonceClient | nonceServer | pubkeyDHServer_len | pubkeyDHServer | DIGSIGN

    pubKeyDHBufferLen = srv.crypto->serializePublicKey(prvKeyDHServer, pubKeyDHBuffer.data());
    
    srv.crypto->generateNonce(nonceServer.data());
    memcpy(nonceServer_t.data(), nonceServer.data(), nonceServer.size());

    byte_index = 0;    
    dim = sizeof(char) + 2*constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferLen;
    unsigned char* last_message = (unsigned char*)malloc(dim);
    if(!last_message) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(&(last_message[byte_index]), &constants::AUTH, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(last_message[byte_index]), nonceServer.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;
    
    memcpy(&(last_message[byte_index]), nonceClient.data(), constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(&(last_message[byte_index]), &pubKeyDHBufferLen, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(last_message[byte_index]), pubKeyDHBuffer.data(), pubKeyDHBufferLen);
    byte_index += pubKeyDHBufferLen;
    
    unsigned char* last_message_signed = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    if(!last_message_signed) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    signed_size = srv.crypto->digsign_sign(last_message, dim, last_message_signed, prvkey_server);
    if(signed_size < 0){
        cerr << RED << "[ERROR] Signature is not valid" << RESET << endl;
        exit(1);
    } else {
        cout << GREEN << "[LOG] Valid Signature " << RESET << endl;
    }

    srv.serverConn->send_message(last_message_signed, sd, signed_size);

    // Generate secret
    cout << GREEN << "[LOG] Generating session key" << RESET << endl;

    unsigned char* temp_session_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if(!temp_session_key) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    srv.crypto->secretDerivation(prvKeyDHServer, pubKeyDHClient, temp_session_key);

    srv.serverConn->addSessionKey(sd, temp_session_key);
    
    cout << YELLOW << "[LOG] Authentication succeeded " << RESET << endl;

    free(temp_session_key);
    free(username);
    free(last_message);
    free(message);
    free(signature);
    free(clear_buf);
    free(last_message_signed);
    return true;   
}

int decrypt_message(Server srv, int sd, unsigned char* message, int dim, vector<unsigned char> &decrypted) {
    int decrypted_size = srv.crypto->decryptMessage(srv.serverConn->getSessionKey(sd), message, dim, decrypted);
    return decrypted_size;
}

int send_message_enc_srv(CryptoOperation* crypto, int fd, unsigned char* key, unsigned char* iv, unsigned char* message, int dim, vector<unsigned char> &encrypted) {
    int ret = 0;

    int encrypted_size = crypto->encryptMessage(key, iv, message, dim, encrypted);

    do {
        ret = send(fd, encrypted.data(), encrypted_size, 0);
        if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            cerr << RED << "[ERROR] send failed" << RESET << endl;
            exit(1);
        } else if (ret == 0) {
            cout << "[LOG] client connection closed" << endl;
            return 0;
        } 
    } while (ret != encrypted_size);

    return ret;
}

bool seeOnlineUsers(Server &srv, int sd, vector<unsigned char> &buffer) {

    int byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + sizeof(int);
    vector<user> users_logged_in = srv.serverConn->getUsersList();
    unsigned char* message = NULL;
    string requesting_user = srv.serverConn->findUserFromSd(sd);

    if(requesting_user.size() == 0) {
        cerr << RED << "[ERROR] receive error" << RESET << endl;
        exit(1);
    }

    buffer.clear();

    for(size_t i = 0; i < users_logged_in.size(); i++) {    
        if( (users_logged_in[i].username.size() == requesting_user.size()) && memcmp(requesting_user.c_str(), users_logged_in[i].username.c_str(), requesting_user.size()) == 0 ) {
            continue;
        } else {
            dim += users_logged_in[i].username.size();
            dim += sizeof(int);
        }
    }

    message = (unsigned char*)malloc(dim);
    if(!message) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(&(message[byte_index]), &constants::ONLINE, sizeof(char));
    byte_index += sizeof(char);

    int dim_message = 0;

    memcpy(&(message[byte_index]), &dim, sizeof(int));
    byte_index += sizeof(int);

    int list_size = users_logged_in.size() - 1;
    memcpy(&(message[byte_index]), &list_size, sizeof(int));
    byte_index += sizeof(int);

    for(size_t i = 0; i < users_logged_in.size(); i++) {

        if( (users_logged_in[i].username.size() == requesting_user.size()) && memcmp(requesting_user.c_str(), users_logged_in[i].username.c_str(), requesting_user.size()) == 0) { 
            continue;
        } else {
            int username_size = users_logged_in[i].username.size();

            memcpy(&(message[byte_index]), &username_size, sizeof(int));
            byte_index += sizeof(int);

            memcpy(&(message[byte_index]), users_logged_in[i].username.c_str(), users_logged_in[i].username.size());
            byte_index += users_logged_in[i].username.size();
        }
    }   

    srv.serverConn->generateIV();
    send_message_enc_srv(srv.crypto, sd, srv.serverConn->getSessionKey(sd), srv.serverConn->getIV(), message, byte_index, buffer);

    return true;   
}

int receive_message_enc_srv(Server srv, int sd, unsigned char* message, vector<unsigned char> &decrypted) {
    int message_len;

    do {
        message_len = recv(sd, message, constants::MAX_MESSAGE_SIZE-1, 0);
        
        if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            cerr << RED << "[ERROR] receive error" << RESET << endl;
            exit(1);
        } else if (message_len == 0) {
            cout << "[LOG] client connection closed" << endl;
            return 0;
        } 
    } while (message_len < 0);

    int decrypted_size = srv.crypto->decryptMessage(srv.serverConn->getSessionKey(sd), message, message_len, decrypted);

    return decrypted_size;
}

bool requestToTalk(Server &srv, int sd, unsigned char* buffer, int buf_len) {

    int byte_index = 0;    
    char opCode;
    int username_to_talk_to_size = 0;
    int username_size = 0;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyClientBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> keyClientDHBuffer;
    int pubKeyBufferLen = 0;
    int keyDHBufferLen = 0;
    vector<user> users_logged_in = srv.serverConn->getUsersList();
    vector<unsigned char> decrypted;
    vector<unsigned char> encrypted;

    decrypted.resize(buf_len);
    srv.crypto->decryptMessage(srv.serverConn->getSessionKey(sd), buffer, buf_len, decrypted);

    memcpy(&opCode, &(decrypted.data()[byte_index]), sizeof(char));
    byte_index += sizeof(char);

    memcpy(&username_to_talk_to_size, &(decrypted.data()[byte_index]), sizeof(int));
    byte_index += sizeof(int);

    unsigned char* username_to_talk_to = (unsigned char*)malloc(username_to_talk_to_size);
    if(!username_to_talk_to) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(username_to_talk_to, &(decrypted.data()[byte_index]), username_to_talk_to_size);
    byte_index += username_to_talk_to_size;

    string username_string = srv.serverConn->findUserFromSd(sd);
    username_size = username_string.size();
    unsigned char* username = (unsigned char*)malloc(username_size);
    if(!username) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    memcpy(username, (unsigned char*)username_string.c_str(), username_size);

    srv.serverConn->generateIV();

    for(auto us : srv.serverConn->getActiveChats()) {
        if( (memcmp(us->username_1, username, username_size) == 0 || 
            memcmp(us->username_2, username, username_size) == 0) || 
            (memcmp(us->username_1, username_to_talk_to, username_to_talk_to_size) == 0 || 
            memcmp(us->username_2, username_to_talk_to, username_to_talk_to_size) == 0) )
            {
                cout << RED << "[ERROR] user already chatting" << RESET << endl;
                free(username_to_talk_to);
                free(username);

                unsigned char* already_chatting = (unsigned char*)malloc(sizeof(char));
                if(!already_chatting) {
                    cerr << RED << "[ERROR] malloc error" << RESET << endl;
                    exit(1);
                }

                already_chatting[0] = 'n';

                encrypted.resize(sizeof(char));
                send_message_enc_srv(srv.crypto, sd, srv.serverConn->getSessionKey(sd), srv.serverConn->getIV(), already_chatting, sizeof(char), encrypted);

                free(already_chatting);
                return true;
            }
    }

    byte_index = 0;    
    int dim = sizeof(char) + sizeof(int) + username_size;
    unsigned char* message = (unsigned char*)malloc(dim); 
    if(!message) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    } 

    memcpy(&(message[byte_index]), &constants::REQUEST, sizeof(char));
    byte_index += sizeof(char);

    memcpy(&(message[byte_index]), &username_size, sizeof(int));
    byte_index += sizeof(int);

    memcpy(&(message[byte_index]), username, username_size);
    byte_index += username_size;

    int user_to_talk_to_sd = -1;
    for(int i = 0; i < (int)users_logged_in.size(); i++) {
        if( strncmp(users_logged_in[i].username.c_str(), reinterpret_cast<const char*>(username_to_talk_to), users_logged_in[i].username.size()) == 0 ) {
            encrypted.clear();
            send_message_enc_srv(srv.crypto, users_logged_in[i].sd, srv.serverConn->getSessionKey(users_logged_in[i].sd), srv.serverConn->getIV(), message, dim, encrypted);
            user_to_talk_to_sd = users_logged_in[i].sd;
        }
    }

    unsigned char* response = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    if(!response) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    decrypted.clear();

    int ret = receive_message_enc_srv(srv, user_to_talk_to_sd, response, decrypted);
    if(ret == 0) {
        cout << RED <<"[LOG] client disconnected" << RESET << endl;
        return false;
    }

    byte_index = 0;
    memcpy(&opCode, &(response[byte_index]), sizeof(char));
    byte_index += sizeof(char);

    byte_index = 0;
    message = (unsigned char*)malloc(dim);
    if(!message) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    if(opCode == constants::ACCEPTED) {   
        //Recuperare chiave pubblica utente della risposta

        byte_index += sizeof(char);

        std::stringstream filename_stream;
        std::stringstream username_string;

        for(int i = 0; i < username_to_talk_to_size; i++) {
            filename_stream << username_to_talk_to[i];
            username_string << username_to_talk_to[i];
        }

        cout << endl;

        filename_stream << "_pubkey.pem";

        string filename = filename_stream.str();

        string filename_dir = "keys/public/" + filename;
            
        FILE* file;
        file = fopen(filename_dir.c_str(), "r");
        if(!file) {
            cerr << RED << "[ERROR] file not found" << RESET << endl;
            exit(1);
        }

        EVP_PKEY *pubkey_client_B = PEM_read_PUBKEY(file, NULL, NULL, NULL);
        if(!pubkey_client_B){
            fclose(file);
            cerr << RED << "[ERROR] error reading pubkey" << RESET << endl;
            exit(1);
        }

        // Serializzare chiave pubblica
        pubKeyBufferLen = srv.crypto->serializePublicKey(pubkey_client_B, pubKeyClientBuffer.data());
        int pubKeyBufferLen = srv.crypto->serializePublicKey(pubkey_client_B, pubKeyClientBuffer.data());

        // Cambiare dim
        memcpy(&keyDHBufferLen, &(decrypted.data()[byte_index]), sizeof(int));
        byte_index += sizeof(int);

        memcpy(keyClientDHBuffer.data(), &(decrypted.data()[byte_index]), keyDHBufferLen);
        byte_index+= keyDHBufferLen;

        dim = sizeof(char) + sizeof(int) + keyDHBufferLen + sizeof(int) + pubKeyBufferLen;
        
        free(message);

        byte_index = 0;
        message = (unsigned char*)malloc(dim);
        if(!message) {
            cerr << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        memcpy(&(message[byte_index]), &constants::ACCEPTED, sizeof(char));
        byte_index += sizeof(char);

        memcpy(&(message[byte_index]), &keyDHBufferLen, sizeof(int));
        byte_index += sizeof(int);

        memcpy(&(message[byte_index]), keyClientDHBuffer.data(), keyDHBufferLen);
        byte_index += keyDHBufferLen;

        memcpy(&(message[byte_index]), &pubKeyBufferLen, sizeof(int));
        byte_index += sizeof(int);

        memcpy(&(message[byte_index]), pubKeyClientBuffer.data(), pubKeyBufferLen);
        byte_index += pubKeyBufferLen;
   
    } else {
        // liberare tutto e inviare risposta negativa
        memcpy(&(message[byte_index]), &constants::REFUSED, sizeof(char));
        byte_index += sizeof(char);
    }

    encrypted.clear();
    send_message_enc_srv(srv.crypto, sd, srv.serverConn->getSessionKey(sd), srv.serverConn->getIV(), message, byte_index, encrypted);

    int sd_1 = 0;
    int sd_2 = 0;

    for(auto user : users_logged_in) {
        if(memcmp(user.username.c_str(), username, username_size) == 0) {
            sd_1 = user.sd;
        }

        if(memcmp(user.username.c_str(), username_to_talk_to, username_to_talk_to_size) == 0) {
            sd_2 = user.sd;
        }
    }

    userChat *new_chat = new userChat(username, username_size ,sd_1, username_to_talk_to, username_to_talk_to_size, sd_2);
    if(!new_chat) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    srv.serverConn->insertChat(new_chat);

    free(message);
    free(username_to_talk_to);
    free(username);
    free(response);
    return true;       
}

bool chatting(Server srv, int sd, unsigned char* buffer, int msg_len) {

    unsigned char* message_received = NULL;
    array<unsigned char, constants::IV_LEN> iv;
    vector<unsigned char> decrypted;
    vector<unsigned char> encrypted;
    int byte_index = 0;
    int sd_to_send = -1;

    sd_to_send = srv.serverConn->findSd(sd);
    if(sd_to_send == -1) {
        cout << RED << "[ERROR] no chat found" << RESET << endl;
        return false;
    }

    int decrypted_size = srv.crypto->decryptMessage(srv.serverConn->getSessionKey(sd), buffer, msg_len, decrypted);

    message_received = (unsigned char*)malloc(decrypted_size);
    if(!message_received) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }
    
    memcpy(message_received, &decrypted.data()[byte_index], decrypted_size);
    byte_index += decrypted_size;

    byte_index = sizeof(char);
    memcpy(iv.data(), &decrypted.data()[byte_index], constants::IV_LEN);
    byte_index += constants::IV_LEN;

    int encrypted_size = send_message_enc_srv(srv.crypto, sd_to_send, srv.serverConn->getSessionKey(sd_to_send), iv.data(), decrypted.data(), decrypted_size, encrypted);
    if(encrypted_size <= 0) {
        cout << RED << "[ERROR] encryption failed" << RESET << endl;
        return false;
    }

    free(message_received);
    return true;   
}

bool closingChat(Server srv, int sd, unsigned char* buffer, int dim) {
    vector<userChat*> chats = srv.serverConn->getActiveChats();
    int index = 0;
    int other_sd = 0;
    vector<unsigned char> decrypted;
    vector<unsigned char> encrypted;
    unsigned char* message_received;
    int byte_index = 0;
    array<unsigned char, constants::IV_LEN> iv;

    for(auto chat : chats) {
        if(chat->sd_1 == sd) {
            other_sd = chat->sd_2;
            cout << MAGENTA << "[DEBUG] chat found and deleted" << RESET << endl;
            break;
        } else if(chat->sd_2 == sd) {
            other_sd = chat->sd_1;
            cout << MAGENTA << "[DEBUG] chat found and deleted" << RESET << endl;
            break;
        }

        index++;
    }

    int decrypted_size = srv.crypto->decryptMessage(srv.serverConn->getSessionKey(sd), buffer, dim, decrypted);

    message_received = (unsigned char*)malloc(decrypted_size);
    if(!message_received) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }
    
    memcpy(message_received, &decrypted.data()[byte_index], decrypted_size);
    byte_index += decrypted_size;

    byte_index = sizeof(char);
    memcpy(iv.data(), &decrypted.data()[byte_index], constants::IV_LEN);
    byte_index += constants::IV_LEN;

    int encrypted_size = send_message_enc_srv(srv.crypto, other_sd, srv.serverConn->getSessionKey(other_sd), iv.data(), decrypted.data(), decrypted_size, encrypted);
    if(encrypted_size <= 0) {
        cout << RED << "[ERROR] encryption failed" << RESET << endl;
        return false;
    }

    free(message_received);
    return true;
}

