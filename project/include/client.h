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

int send_message_enc(int masterFD, Client clt, unsigned char* message, int dim, vector<unsigned char> &encrypted) {
    int ret = 0;

    unsigned char* session_key = clt.clientConn->getSessionKey();

    clt.clientConn->generateIV();
    unsigned char* iv = clt.clientConn->getIV();

    encrypted.resize(dim);
    int encrypted_size = clt.crypto->encryptMessage(session_key, iv, message, dim, encrypted);

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

int receive_message_enc(Client clt, unsigned char* message, vector<unsigned char> &decrypted) {
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

    int decrypted_size = clt.crypto->decryptMessage(clt.clientConn->getSessionKey(), message, message_len, decrypted);

    return decrypted_size;
}

bool authentication(Client &clt, string username, string password) {
    X509 *cert;
    EVP_PKEY* user_key = NULL;
    EVP_PKEY *pubKeyServer = NULL;
    EVP_PKEY *pubKeyDHServer = NULL;
    EVP_PKEY *prvKeyDHClient = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    array<unsigned char, NONCE_SIZE> nonceClient;
    unsigned int pubKeyDHBufferLen;
    vector<unsigned char> buffer;
    unsigned char* nonceServer = (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* nonceClient_rec = (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* nonceClient_t = (unsigned char*)malloc(constants::NONCE_SIZE);
    unsigned char* signature = NULL;
    string to_insert;

    string filename = "./keys/private/" + username + "_prvkey.pem";
	
	FILE* file = fopen(filename.c_str(), "r");
	if(!file) {
        cerr << RED << "User does not have a key file" << RESET << endl; 
        exit(1);
    }   

	user_key = PEM_read_PrivateKey(file, NULL, NULL, (void*)password.c_str());
	if(!user_key) {
        cerr << RED << "[ERROR] User does not valid, retry" << RESET << endl; 
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
        cout << RED << "[LOG] client connection closed " << RESET << endl;
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
        cerr << RED << "[ERROR] malloc error on certification buffer" << RESET << endl; 
        exit(1);
    }

    memcpy(cert_buf, &message_received[byte_index], size_cert);
    byte_index += size_cert;

    nonceServer = (unsigned char*)malloc(constants::NONCE_SIZE);
    if(!nonceServer) {
        cerr << RED << "[ERROR] malloc error on nonce server" << RESET << endl; 
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
        cerr << RED << "[ERROR] error in certificate verification" << RESET << endl; 
        exit(1);
    }
    
    cout << GREEN << "[LOG] server certificate verified" << RESET << endl;  

    // print the successful verification to screen, just for debug
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    cout << CYAN << "[DEBUG] certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n" << RESET << endl;
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
        cerr << RED << "[ERROR] invalid signature!" << endl;
        return false;
    } else { 
        cout << GREEN << "[LOG] valid Signature " << RESET << endl;
    }

    //Verificare nonce
    if(memcmp(nonceClient_t, nonceClient_rec, constants::NONCE_SIZE) != 0){
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

    memcpy(nonceClient_t, nonceClient.data(), constants::NONCE_SIZE);

    byte_index = 0;   

    // OPCODE | New_nonce_client | Nonce Server | Pub_key_DH_len | pub_key_DH | dig_sign

    dim = sizeof(char) + constants::NONCE_SIZE + constants::NONCE_SIZE + sizeof(int) + pubKeyDHBufferLen;

    message_sent = (unsigned char*)malloc(dim);
    if(!message_sent) {
        cerr << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
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
        cout << RED  << "[LOG] server disconnected " << RESET << endl;
        free(last_message_received);
        return false;
    }  

    char opCode;
    byte_index = 0;    
    
    memcpy(&(opCode), &last_message_received[byte_index], sizeof(char));
    byte_index += sizeof(char);

    memcpy(nonceServer, &last_message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    memcpy(nonceClient.data(), &last_message_received[byte_index], constants::NONCE_SIZE);
    byte_index += constants::NONCE_SIZE;

    if(memcmp(nonceClient_t, nonceClient.data(), constants::NONCE_SIZE) != 0){
        cerr << RED << "[ERROR] nonce received is not valid" << RESET << endl;
        exit(1);
    } else {
        cout << GREEN << "[LOG] nonce verified " << RESET << endl;
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
        cerr << RED << "[ERROR] invalid signature" << RESET << endl;
        return false;
    } else {
        cout << GREEN << "[LOG] valid signature " << RESET << endl;
    }

    cout << GREEN << "[LOG] Generating session key " << RESET << endl;

    clt.crypto->secretDerivation(prvKeyDHClient, pubKeyDHServer, tempBuffer.data());
    clt.clientConn->addSessionKey(tempBuffer.data());

    cout << YELLOW << "[LOG] Authentication succeeded " << RESET << endl;

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

bool receiveRequestToTalk(Client &clt, unsigned char* msg, int msg_len) {

    unsigned int keyBufferDHLen = 0;
    EVP_PKEY *keyDH = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> keyDHBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    vector<unsigned char> decrypted;
    vector<unsigned char> encrypted; 
    int byte_index = 0;
    unsigned char* username = NULL;
    unsigned int username_size = 0;
    unsigned char* response_to_request = NULL;
    unsigned char response = 'n';
    int dim = 0;

    clt.crypto->decryptMessage(clt.clientConn->getSessionKey(), msg, msg_len, decrypted);

    byte_index += sizeof(char);

    memcpy(&(username_size), &decrypted.data()[byte_index], sizeof(int));
    byte_index += sizeof(int);

    if(username_size < 0 || username_size > constants::MAX_MESSAGE_SIZE) {
        cerr << RED << "[ERROR] username size error" << RESET << endl;
        return false;
    }

    username = (unsigned char*)malloc(username_size);
    if(username == NULL) {
        cerr << RED << "[ERROR] username malloc error" << RESET << endl;
        return false;
    }

    memcpy(username, &decrypted.data()[byte_index], username_size);
    byte_index += username_size;

    unsigned char* username_to_copy = clt.clientConn->getUsername();
    int username_to_copy_size = clt.clientConn->getUsernameSize();

    if( (username_size == username_to_copy_size) && memcmp(username_to_copy, username, username_size) == 0) {
        cout << RED << "[ERROR] you're trying to speak with yourself, insert a valid username" << RESET << endl;
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

        cout << GREEN << "[LOG] starting the chat" << RESET << endl;

        clt.clientConn->setCurrentChat(username, username_size, username_to_copy, username_to_copy_size);

        clt.crypto->keyGeneration(keyDH);
        keyBufferDHLen = clt.crypto->serializePublicKey(keyDH, keyDHBuffer.data());

        clt.clientConn->setKeyDHBufferTemp(keyDH, keyBufferDHLen);

        dim = sizeof(char) + sizeof(int) + keyBufferDHLen;
        response_to_request = (unsigned char*)malloc(dim); 
        if(response_to_request == NULL) {
            cerr << RED << "[ERROR] malloc response error" << RESET << endl;
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

    } else {
        cout << RED << "refused :(" << RESET << endl;

        dim = sizeof(char);

        response_to_request = (unsigned char*)malloc(dim); 
        if(response_to_request == NULL) {
            cerr << RED << "[ERROR] malloc response error" << RESET << endl;
            return false;
        }

        byte_index = 0;
        memcpy(&(response_to_request[byte_index]), &constants::REFUSED, sizeof(char));
        byte_index += sizeof(char);
    }  

    int ret = send_message_enc(clt.clientConn->getMasterFD(), clt, response_to_request, dim, encrypted);
    if(ret <= 0) {
        return false;
    }

    free(response_to_request);
    free(username);
    return true;
}

void print_unsigned_array(unsigned char* array, int dim) {
    for(int i = 0; i < dim; i++) {
        cout << array[i];
    }
}

void chat(Client clt) {
    fd_set fds;
    string message;
    unsigned char* to_send;
    vector<unsigned char> encrypted;
    vector<unsigned char> decrypted;
    vector<unsigned char> clear;
    unsigned char* buffer = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE);
    unsigned char* iv = (unsigned char*)malloc(constants::IV_LEN);
    int maxfd;
    int ret = -1;

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

            if(message.compare(":q!") == 0) {
                break;
            }

            int byte_index = 0;
            unsigned char* tempBuffer = (unsigned char*)malloc(message.size() + sizeof(char));

            memcpy(&(tempBuffer[byte_index]), &constants::CHAT, sizeof(char));
            byte_index += sizeof(char);

            memcpy(&(tempBuffer[byte_index]), message.c_str(), message.size());
            byte_index += message.size();

            clt.clientConn->generateIV(iv);
            int encrypted_size = clt.crypto->encryptMessage(clt.clientConn->getMyCurrentChat()->chat_key, iv, tempBuffer, message.size() + sizeof(char), encrypted);
            if(encrypted_size < 0 || encrypted_size > constants::MAX_MESSAGE_SIZE) {
                cout << RED << "[ERROR] message not valid" << RESET << endl;
                exit(1);
            }

            byte_index = 0;
            int dim_send = encrypted_size;
            to_send = (unsigned char*)malloc(dim_send);
            if(!to_send) {
                cout << RED << "[ERROR] malloc error" << RESET << endl;
                exit(1);
            }

            memcpy(&(to_send[byte_index]), encrypted.data(), encrypted_size);
            byte_index += encrypted_size;

            encrypted.clear();

            ret = send_message_enc(clt.clientConn->getMasterFD(), clt, to_send, dim_send, encrypted);

            if(ret <= 0) {
                cerr << RED << "[ERROR] error during the send encrypted" << RESET << endl;
                return;
            }

            message.clear();
        }

        if(FD_ISSET(clt.clientConn->getMasterFD(), &fds)) {
            
            ret = receive_message_enc(clt, buffer, decrypted);

            int decrypted_size = clt.crypto->decryptMessage(clt.clientConn->getMyCurrentChat()->chat_key, decrypted.data(), ret, clear);

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

            // padding: 
            /*
                *********
                message *
                *********
            */
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
    unsigned char* peerKeyDHBuffer;
    unsigned char* peerPubKeyBuffer;  
    EVP_PKEY *peerKeyDH = NULL;
    EVP_PKEY *sessionDHKey = NULL;
    array<unsigned char, constants::MAX_MESSAGE_SIZE> keyDHBuffer;
    int keyDHBufferLen = 0;
    vector<unsigned char> encrypted;
    vector<unsigned char> decrypted;

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

    int ret = send_message_enc(clt.clientConn->getMasterFD(), clt, message, dim, encrypted);
    if(ret <= 0) {
        return;
    }

    unsigned char* response = (unsigned char*)malloc(constants::MAX_MESSAGE_SIZE); 
     
    cout << "*** waiting for response *** " << endl;

    ret = receive_message_enc(clt, response, decrypted);
    if (ret == 0) {
        cout << RED << "[LOG] client connection closed" << RESET << endl;
        free(response);
        return;
    } 

    // Cambiare controllo con l'opcode corretto
    if(response[0] == constants::ACCEPTED) {
        cout << GREEN << "[LOG] request accepted, starting the chat" << RESET << endl;
        cout << "---------------------------------------" << endl;
        cout << "\n-------Chat-------" << endl;

        clt.clientConn->setCurrentChat((unsigned char*)username_to_contact.c_str(), username_to_contact.size(), (unsigned char*)username.c_str(), username.size());

        byte_index = 0;

        byte_index += sizeof(char);

        memcpy(&(peerKeyDHLen), &decrypted.data()[byte_index], sizeof(int));
        byte_index += sizeof(int);

        peerKeyDHBuffer = (unsigned char*)malloc(peerKeyDHLen);
        if(!peerKeyDHBuffer) {
            cout << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        memcpy(peerKeyDHBuffer, &decrypted.data()[byte_index], peerKeyDHLen);
        byte_index += peerKeyDHLen;

        clt.crypto->deserializePublicKey(peerKeyDHBuffer, peerKeyDHLen, peerKeyDH);

        memcpy(&(peerPubKeyLen), &decrypted.data()[byte_index], sizeof(int));
        byte_index += sizeof(int);

        peerPubKeyBuffer = (unsigned char*)malloc(peerPubKeyLen);
        if(!peerPubKeyBuffer) {
            cout << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);
        }

        memcpy(peerPubKeyBuffer, &decrypted.data()[byte_index], peerPubKeyLen);
        byte_index += peerPubKeyLen;

        clt.crypto->deserializePublicKey(peerPubKeyBuffer, peerPubKeyLen, clt.clientConn->getMyCurrentChat()->pubkey_1);

        // Costruire chiave di sessione prvDH

        array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;

        clt.crypto->keyGeneration(sessionDHKey);
        clt.crypto->secretDerivation(sessionDHKey, peerKeyDH, tempBuffer.data());

        // prima era
        // clt.crypto->secretDerivation(sessionDHKey, peerKeyDH, tempBuffer.data());
        // senza fare la keyGeneration, ma quando era inizializzato sessionDHKey?

        memcpy(clt.clientConn->getMyCurrentChat()->chat_key, tempBuffer.data(), EVP_MD_size(EVP_sha256()));

        //Perchè così serializzata?!
        if(!clt.clientConn->getMyCurrentChat()->chat_key) {
            cout << RED << "[ERROR] malloc error" << RESET << endl;
            exit(1);    
        } else {
            cout << MAGENTA << "[DEBUG] chat key:" << endl;
            BIO_dump_fp(stdout, (const char*)clt.clientConn->getMyCurrentChat()->chat_key, EVP_MD_size(EVP_sha256()));
            cout << RESET << endl;
        }

        //Costruire e inviare mia chiave DH
        // opcode | keyDHlen | keyDH

        keyDHBufferLen = clt.crypto->serializePublicKey(sessionDHKey, keyDHBuffer.data());
        dim = sizeof(char) + sizeof(int) + keyDHBufferLen;
        free(message);
        
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

        memcpy(&(message[byte_index]), keyDHBuffer.data(), keyDHBufferLen);
        byte_index += keyDHBufferLen;

        //Inviare messaggio
        encrypted.clear();
        ret = send_message_enc(clt.clientConn->getMasterFD(), clt, message, byte_index, encrypted);
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

