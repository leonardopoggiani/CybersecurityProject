#include "include/crypto.h"
#include "include/color.h"


using namespace std;

//Message Digest for digital signature and hash
const EVP_MD* md = EVP_sha256();

void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

void CryptoOperation::generateNonce(unsigned char* nonce) {
    if(RAND_poll() != 1)
        throw runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(nonce, constants::NONCE_SIZE) != 1)
        throw runtime_error("An error occurred in RAND_bytes.");
        
    cout << "nonce generated" << endl;
}

//CERTIFICATES

void CryptoOperation::loadCertificate(X509*& cert, string path){
    
    string path_str = "./certificates/" + path + ".pem";
    FILE *file = fopen(path_str.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred while opening the file.");
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    if(!cert){
        fclose(file);
        throw runtime_error("An error occurred while reading the pem certificate.");
    }

    fclose(file);
}

unsigned int CryptoOperation::serializeCertificate(X509* cert, unsigned char* cert_buf){
    int cert_size = i2d_X509(cert,&cert_buf);
    if(cert_size < 0)
        throw runtime_error("An error occurred during the writing of the certificate.");

    return cert_size;
}

void CryptoOperation::deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff){

    cout << "cert_len" << cert_len << endl;
    buff = d2i_X509(NULL,(const unsigned char**)&cert_buff,cert_len);
    if(!buff)
        throw runtime_error("An error occurred during the reading of the certificate.");
}

void CryptoOperation::loadCRL(X509_CRL*& crl){
    FILE* file = fopen("certificates/FoundationsOfCybersecurity_crl.pem", "r");

    if(!file)
        throw runtime_error("An error occurred opening crl.pem.");

    crl = PEM_read_X509_CRL(file, NULL, NULL, NULL); 

    if(!crl) { 
        fclose(file);
        throw runtime_error("An error occurred reading the crl from file");
    }

    fclose(file);
}

bool CryptoOperation::verifyCertificate(X509* cert_to_verify) {
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509* ca_cert;
    X509_STORE* store;
    X509_CRL* crl;

    loadCertificate(ca_cert, "ca_cert");
    loadCRL(crl);

    store = X509_STORE_new();
    if(!store)
        throw runtime_error("An error occured during the allocation of the store");
    
    try {
        if(X509_STORE_add_cert(store, ca_cert)<1)
            throw runtime_error("An error occurred adding the certification to the store");
    
        if(X509_STORE_add_crl(store, crl)<1)
            throw runtime_error("An error occurred adding the crl to the store");
        
        if(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK)<1)
            throw runtime_error("An error occurred adding the flags to the store");
        
        if(X509_STORE_CTX_init(ctx, store, cert_to_verify, NULL)==0)
            throw runtime_error("An error occurred during the initialization of the context");
    } catch(const exception& e) {
        X509_STORE_free(store);
        throw;
    }

    if(X509_verify_cert(ctx) != 1) { 
        int ret =  X509_STORE_CTX_get_error(ctx);
        cout << X509_verify_cert_error_string(ret) << endl;   
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return false;
    }

    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);
    return true;
}

//KEYS

void CryptoOperation::readPrivateKey(EVP_PKEY *&prvKey) {
    FILE* file;
    file = fopen("./keys/srv_prvkey.pem", "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");
    prvKey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!prvKey){
        fclose(file);
        throw runtime_error("An error occurred while reading the private key.");
    }

    fclose(file);
}

void CryptoOperation::readPrivateKey(string usr, string pwd, EVP_PKEY *& prvKey) {
    FILE* file;
    string path;
    path = "./keys/private/" + usr + "_prvkey.pem";
    file = fopen(path.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");
    prvKey = PEM_read_PrivateKey(file, NULL, NULL, (char*)pwd.c_str());
    if(!prvKey){
        fclose(file);
        throw runtime_error("An error occurred while reading the private key.");
    }

    fclose(file);
}

void CryptoOperation::readPublicKey(string user, EVP_PKEY *&pubKey) {
    FILE* file;
    string path = "./keys/" + user + "_pubkey.pem";
    file = fopen(path.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");
    pubKey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubKey){
        fclose(file);
        throw runtime_error("An error occurred while reading the private key.");
    }

    fclose(file);
}

void CryptoOperation::getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey){
    pubkey = X509_get_pubkey(cert);
    if(!pubkey)
        throw runtime_error("An error occurred while getting the key from the certificate.");
}

unsigned int CryptoOperation::serializePublicKey(EVP_PKEY *pub_key, unsigned char *pubkey_buf){
    BIO *mbio;
    unsigned char *buffer;
    long pubkey_size; 

    mbio = BIO_new(BIO_s_mem());
    if(!mbio)
        throw runtime_error("An error occurred during the creation of the bio.");

    if(PEM_write_bio_PUBKEY(mbio,pub_key) != 1){
        BIO_free(mbio);
        throw runtime_error("An error occurred during the writing of the public key into the bio.");
    }

    pubkey_size = BIO_get_mem_data(mbio, &buffer);
    memcpy(pubkey_buf, buffer, pubkey_size);

    if(pubkey_size < 0 || pubkey_size > UINT_MAX) {
        BIO_free(mbio);
        throw runtime_error("An error occurred during the reading of the public key.");
    }

    BIO_free(mbio);

    return pubkey_size;
}

void CryptoOperation::deserializePublicKey(unsigned char* pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey){
    BIO *mbio;

    mbio = BIO_new(BIO_s_mem());

    if(!mbio)
        throw runtime_error("An error occurred during the creation of the bio.");

    if(BIO_write(mbio,pubkey_buf,pubkey_size) <= 0)
        throw runtime_error("An error occurred during the writing of the bio.");

    pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);

    if(!pubkey){
        BIO_free(mbio);
        throw runtime_error("An error occurred during the reading of the public key from the bio.");
    }

    BIO_free(mbio);
}

// DH parameters
void CryptoOperation::buildParameters(EVP_PKEY *&dh_params) {
    EVP_PKEY_CTX* pctx;
    
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!pctx)
        throw runtime_error("An error occurred during the creation of the context");

    if( EVP_PKEY_paramgen_init(pctx) < 1 )
        throw runtime_error("An error occurred during the initialization of the parameters");

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_X9_62_prime256v1);

    if( EVP_PKEY_paramgen(pctx, &dh_params) < 1 ) {
        throw runtime_error("An error occurred during the generation of the parameters");
    }

    EVP_PKEY_CTX_free(pctx);
}

void CryptoOperation::keyGeneration(EVP_PKEY *&my_prvkey){
    EVP_PKEY *dh_params = NULL;
    EVP_PKEY_CTX *ctx;

    buildParameters(dh_params);

    ctx = EVP_PKEY_CTX_new(dh_params,NULL);
    if(!ctx)
        throw runtime_error("An error occurred during the creation of the context");

    try
    {
        if(EVP_PKEY_keygen_init(ctx) < 1) 
            throw runtime_error("An error occurred during the intialization of the context");

        if(EVP_PKEY_keygen(ctx, &my_prvkey) < 1)
            throw runtime_error("An error occurred during the intialization of the context");

    } catch(const exception& e) {
        EVP_PKEY_CTX_free(ctx);
        throw;
    }

    EVP_PKEY_CTX_free(ctx);
}

unsigned int CryptoOperation::digsign_sign(unsigned char *message, unsigned int messageLen, unsigned char *buffer, EVP_PKEY *prvKey) {
    unsigned char *signature; 
    unsigned int signLen;

    signature = new(nothrow) unsigned char[EVP_PKEY_size(prvKey)];
    if(!signature) {
        throw runtime_error("Buffer not allocated correctly");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("Context not initialized");
    }

    try {
        if(EVP_SignInit(ctx, EVP_sha256()) != 1) {
            throw runtime_error("Error inizializing the sign");
        }
        if(EVP_SignUpdate(ctx, message, messageLen) != 1) {
            throw runtime_error("Error updating the sign");
        }
        if(EVP_SignFinal(ctx, signature, &signLen, prvKey) != 1){
            throw runtime_error("Error finalizing the sign");
        }

        memcpy(buffer, message, messageLen);
        memcpy(buffer + messageLen, &signLen, sizeof(int));
        memcpy(buffer + messageLen + sizeof(int), signature, signLen);

        delete[] signature;
        EVP_MD_CTX_free(ctx);
    } catch(const exception& e) {
        delete[] signature;
        EVP_MD_CTX_free(ctx);
        throw;
    }

    return signLen + messageLen;
}

bool CryptoOperation::digsign_verify(unsigned char *signature, unsigned int signLen, unsigned char *message, unsigned int messageLen, EVP_PKEY *pubKey) {
    int ret = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("Context not initialized");
    }

    try {
        if(EVP_VerifyInit(ctx, EVP_sha256()) != 1){
            throw runtime_error("Error initializing the signature verification");
        }
        if(EVP_VerifyUpdate(ctx, message, messageLen) != 1) {
            throw runtime_error("Error updating the signature verification");
        }
        ret = EVP_VerifyFinal(ctx, signature, signLen, pubKey); 
        EVP_MD_CTX_free(ctx);
        if(ret != 1) { 
            return false;
        }
    } catch(const exception& e) {
        EVP_MD_CTX_free(ctx);
        throw;
    }
    return true;
}


unsigned int CryptoOperation::encryptMessage(connection* conn, unsigned char *msg, unsigned int msg_len, unsigned char *buffer) {
    unsigned char *ciphertext;
    uint32_t counter = 0;
    unsigned char tag[constants::TAG_LEN];
    unsigned char* iv = (unsigned char*)malloc(constants::IV_LEN);
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned int finalSize = 0;
    unsigned int start = 0;
    int len = 0;
    int ciphr_len = 0;
    int ret = 0;

    finalSize = msg_len + 2*constants::TAG_LEN + constants::IV_LEN;

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        throw runtime_error("An error occurred while creating the context."); 
    
    ciphertext = new (nothrow) unsigned char[constants::MAX_MESSAGE_SIZE];

    if(!ciphertext){
        throw runtime_error("An error occurred initilizing the buffer");
    }
    try {
        conn->generateIV();

        if(EVP_EncryptInit(ctx, EVP_aes_128_gcm(), conn->getSessionKey(), conn->getIV()) != 1)
            throw runtime_error("An error occurred while initializing the context.");
            
        // AAD: Insert the counter
        // if(EVP_EncryptUpdate(ctx, NULL, &len, conn->getIV(), constants::IV_LEN) != 1)
        //    throw runtime_error("An error occurred while encrypting the message.");

        // cout << MAGENTA << "[DEBUG] cifrato iv in modo corretto " << RESET << endl;

        // conn->getCounter(&counter);
        // if(EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char*) counter, sizeof(uint16_t)) != 1)
        //    throw runtime_error("An error occurred while encrypting the message.");

        // cout << MAGENTA << "[DEBUG] cifrato counter in modo corretto " << RESET << endl;
            
        unsigned char* mex = (unsigned char*)malloc(16);
        for(int i = 0; i < 16; i++) {
            mex[i] = 'a';
        }

        ret = EVP_EncryptUpdate(ctx, NULL, &len, mex, 16);
        if(ret != 1) {
            throw runtime_error("An error occurred while encrypting the message.");
        }
        ciphr_len = len;

        cout << MAGENTA << "[DEBUG] cifrato messaggio in modo corretto " << RESET << endl;

        if(EVP_EncryptFinal(ctx, ciphertext + len, &len) != 1)
            throw runtime_error("An error occurred while finalizing the ciphertext.");
        ciphr_len += len;

        //Get the tag
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, constants::TAG_LEN, tag) != 1)
            throw runtime_error("An error occurred while getting the tag.");
        
        if(ciphr_len < 0)
            throw runtime_error("An error occurred, negative ciphertext length.");
        
        // if(ciphr_len > UINT_MAX - IV_SIZE - TAG_SIZE - sizeof(uint16_t))
        //    throw runtime_error("An error occurred, ciphertext length too big.");
        
        memcpy(buffer+start, &(constants::CHAT), sizeof(char));
        start += sizeof(char);

        // memcpy(buffer+start, &msg_len, sizeof(int));
        msg_len = 16;
        memcpy(buffer+start, &msg_len, sizeof(int));
        start += sizeof(int);

        int prova = 0;
        memcpy(&prova, buffer + sizeof(char), sizeof(int));

        // memcpy(buffer+start, &counter, sizeof(uint32_t));
        // start += sizeof(uint32_t);
        memcpy(buffer+start, ciphertext, ciphr_len);
        start += ciphr_len;
        memcpy(buffer+start, conn->getIV(), constants::IV_LEN);
        start += constants::IV_LEN;
        memcpy(buffer+start, tag, constants::TAG_LEN);
        start += constants::TAG_LEN;

    } catch(const exception& e) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return start;
}

unsigned int CryptoOperation::decryptMessage(connection* conn, unsigned char *msg, unsigned int msg_len, unsigned char *buffer) {
    unsigned char recv_iv[constants::IV_LEN];
    unsigned char recv_tag[constants::TAG_LEN];
    const unsigned char* counter = (unsigned char*)malloc(sizeof(uint32_t));
    unsigned char *ciphr_msg;
    unsigned char *tempBuffer;
    EVP_CIPHER_CTX *ctx;
    int ret = 0;
    int len = 0;
    int pl_len = 0;
    char opCode;
    int ciphr_len = 0;
    
    if(msg_len > constants::MAX_MESSAGE_SIZE)
        throw runtime_error("Message too big.");

    ciphr_msg = new (nothrow) unsigned char[constants::MAX_MESSAGE_SIZE];

    if(!ciphr_msg)
        throw runtime_error("An error occurred while allocating the array for the ciphertext.");

    tempBuffer = new (nothrow) unsigned char[constants::MAX_MESSAGE_SIZE];
    if(!tempBuffer)
        throw runtime_error("An error occurred while allocating the temporary array for the ciphertext.");

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        delete[] ciphr_msg;
        throw runtime_error("An error occurred while creating the context.");
    } 

    try {
        memcpy(&opCode, msg, sizeof(char));
        memcpy(&ciphr_len, msg + sizeof(char), sizeof(int));
        memcpy(ciphr_msg, msg  + sizeof(char) + sizeof(int), ciphr_len);

        memcpy(recv_iv, msg + sizeof(char) + sizeof(int) + ciphr_len, constants::IV_LEN);
        // memcpy(&counter, msg + sizeof(char) + sizeof(int) + constants::IV_LEN, sizeof(uint32_t));
        memcpy(recv_tag, msg  + sizeof(char) + sizeof(int) + ciphr_len + constants::IV_LEN, constants::TAG_LEN);

        // if(!s.verifyFreshness(bufferCounter)){
        //    throw runtime_error("Freshness not confirmed.");
        // }

        if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), conn->getSessionKey(), recv_iv))
            throw runtime_error("An error occurred while initializing the context.");
        
        // if(!EVP_DecryptUpdate(ctx, NULL, &len, recv_iv, constants::IV_LEN))
        //     throw runtime_error("An error occurred while getting AAD header.");

        // if(!EVP_DecryptUpdate(ctx, NULL, &len, counter, sizeof(uint32_t)))
        //     throw runtime_error("An error occurred while getting AAD header.");
        
        if(!EVP_DecryptUpdate(ctx, tempBuffer, &len, ciphr_msg, ciphr_len))
            throw runtime_error("An error occurred while decrypting the message");
        pl_len = len;

        cout << "ciphr_len: " << ciphr_len << endl;
        for(int i = 0; i < ciphr_len; i++) {
            cout << ciphr_msg[i];
        }
        cout << endl;

        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, constants::TAG_LEN, recv_tag))
            throw runtime_error("An error occurred while setting the expected tag.");
        
        ret = EVP_DecryptFinal(ctx, tempBuffer + pl_len, &len);

        memcpy(buffer, tempBuffer, pl_len);
    } catch(const exception& e) {
        delete[] ciphr_msg;
        delete[] tempBuffer;
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    delete[] ciphr_msg;
    delete[] tempBuffer;
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0){
        pl_len += len;
    } else
        throw runtime_error("An error occurred while decrypting the message.");
    
    // if (pl_len < 0 || pl_len > UINT_MAX) 
    //    throw runtime_error("An error occurred while decrypting the message.");

    return pl_len;
}



void CryptoOperation::computeHash(unsigned char *msg, unsigned int msg_size, unsigned char *digest) {
    unsigned int len;
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    if(!ctx)
        throw runtime_error("An error occurred while creating the context.");

    try {
        if(EVP_DigestInit(ctx, EVP_sha256()) < 1)
            throw runtime_error("An error occurred during the initialization of the digest.");

        if(EVP_DigestUpdate(ctx, msg, msg_size) < 1)
            throw runtime_error("An error occurred during the creation of the digest.");

        if(EVP_DigestFinal(ctx, digest, &len) < 1)
            throw runtime_error("An error occurred during the conclusion of the digest.");
    } catch(const exception& e) {
        EVP_MD_CTX_free(ctx);
        throw;
    }

    EVP_MD_CTX_free(ctx);
}

void CryptoOperation::secretDerivation(EVP_PKEY *my_prvkey, EVP_PKEY *peer_pubkey, unsigned char *buffer) {
    EVP_PKEY_CTX *ctx_drv;
    size_t secretlen;
    unsigned char *secret;

    if(!peer_pubkey)
        throw runtime_error("An error occurred reading the public key.");

    ctx_drv = EVP_PKEY_CTX_new(my_prvkey,NULL);
    if(!ctx_drv)
        throw runtime_error("An error occurred during the creation of the context.");

    if(EVP_PKEY_derive_init(ctx_drv) < 1) {
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred during the intialization of the context.");
    } 

    if(EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred setting the peer's public key.");
    }  
     
    if(EVP_PKEY_derive(ctx_drv, NULL, &secretlen) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred retrieving the secret length.");
    }

    secret = (unsigned char*)OPENSSL_malloc(secretlen);
    if(!secret) {
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred allocating the unsigned char array.");
    }

    if(EVP_PKEY_derive(ctx_drv, secret, &secretlen) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        OPENSSL_free(secret);
        throw runtime_error("An error occurred during the derivation of the secret.");
    }

    EVP_PKEY_CTX_free(ctx_drv);
    computeHash(secret, secretlen, buffer);
    OPENSSL_free(secret);
}

