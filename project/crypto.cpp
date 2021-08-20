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
    if(RAND_poll() != 1) {
        cout << RED << "[ERROR] error in rand_poll" << RESET << endl;
        exit(1);
    }
    if(RAND_bytes(nonce, constants::NONCE_SIZE) != 1) {
        cout << RED << "[ERROR] error in rand_bytes" << RESET << endl;
        exit(1);
    }
        
    cout << "nonce generated" << endl;
}

//CERTIFICATES

void CryptoOperation::loadCertificate(X509*& cert, string path){
    
    string path_str = "./certificates/" + path + ".pem";
    FILE *file = fopen(path_str.c_str(), "r");
    if(!file) {
        cout << RED << "[ERROR] error opening files" << RESET << endl;
        exit(1);
    }
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    if(!cert) {
        fclose(file);
        cout << RED << "[ERROR] error reading pem file" << RESET << endl;
        exit(1);
    }

    fclose(file);
}

unsigned int CryptoOperation::serializeCertificate(X509* cert, unsigned char* cert_buf){
    int cert_size = i2d_X509(cert,&cert_buf);
    if(cert_size < 0) {
        cout << RED << "[ERROR] error writing certificate" << RESET << endl;
        exit(1);
    }

    return cert_size;
}

void CryptoOperation::deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff){

    cout << "cert_len" << cert_len << endl;
    buff = d2i_X509(NULL,(const unsigned char**)&cert_buff,cert_len);
    if(!buff) {
        cout << RED << "[ERROR] error reading certificate" << RESET << endl;
        exit(1);
    }
}

void CryptoOperation::loadCRL(X509_CRL*& crl){
    FILE* file = fopen("certificates/FoundationsOfCybersecurity_crl.pem", "r");

    if(!file){
        cout << RED << "[ERROR] error reading crl.pem file" << RESET << endl;
        exit(1);
    }

    crl = PEM_read_X509_CRL(file, NULL, NULL, NULL); 

    if(!crl) { 
        fclose(file);
        cout << RED << "[ERROR] error reading the crl from file" << RESET << endl;
        exit(1);
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
    if(!store) {
        cout << RED << "[ERROR] error during allocation of the store" << RESET << endl;
        exit(1);
    }
    
    try {
        if(X509_STORE_add_cert(store, ca_cert)<1) {
            cout << RED << "[ERROR] error adding certification to the store" << RESET << endl;
            exit(1);
        }
    
        if(X509_STORE_add_crl(store, crl)<1){
            cout << RED << "[ERROR] error adding crl to the store" << RESET << endl;
            exit(1);
        }
        
        if(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK)<1){
            cout << RED << "[ERROR] error adding flags to the store" << RESET << endl;
            exit(1);
        }
        
        if(X509_STORE_CTX_init(ctx, store, cert_to_verify, NULL)==0){
            cout << RED << "[ERROR] error during initialization of context to the store" << RESET << endl;
            exit(1);
        }
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
    if(!file){
        cout << RED << "[ERROR] private key file doesn't exists" << RESET << endl;
        exit(1);
    }

    prvKey = PEM_read_PrivateKey(file, NULL, NULL, NULL);

    if(!prvKey){
        fclose(file);
        cout << RED << "[ERROR] error reading private key" << RESET << endl;
        exit(1);
    }

    fclose(file);
}

void CryptoOperation::readPrivateKey(string usr, string pwd, EVP_PKEY *& prvKey) {
    FILE* file;
    string path;
    path = "./keys/private/" + usr + "_prvkey.pem";
    file = fopen(path.c_str(), "r");
    if(!file){
        cout << RED << "[ERROR] private key file doesn't exists" << RESET << endl;
        exit(1);
    }

    prvKey = PEM_read_PrivateKey(file, NULL, NULL, (char*)pwd.c_str());

    if(!prvKey){
        fclose(file);
        cout << RED << "[ERROR] error reading private key" << RESET << endl;
        exit(1);
    }

    fclose(file);
}

void CryptoOperation::readPublicKey(string user, EVP_PKEY *&pubKey) {
    FILE* file;
    string path = "./keys/" + user + "_pubkey.pem";
    file = fopen(path.c_str(), "r");
    if(!file){
        cout << RED << "[ERROR] public key file doesn't exists" << RESET << endl;
        exit(1);
    }
    pubKey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubKey){
        fclose(file);
        cout << RED << "[ERROR] error reading public key" << RESET << endl;
        exit(1);
    }

    fclose(file);
}

void CryptoOperation::getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey){
    pubkey = X509_get_pubkey(cert);
    if(!pubkey) {
        cout << RED << "[ERROR] error getting key from certificate" << RESET << endl;
        exit(1);
    }
}

unsigned int CryptoOperation::serializePublicKey(EVP_PKEY *pub_key, unsigned char *pubkey_buf){
    BIO *mbio;
    unsigned char *buffer;
    long pubkey_size; 

    mbio = BIO_new(BIO_s_mem());
    if(!mbio){
        cout << RED << "[ERROR] error during the creation of the bio" << RESET << endl;
        exit(1);
    }

    if(PEM_write_bio_PUBKEY(mbio,pub_key) != 1){
        BIO_free(mbio);
        cout << RED << "[ERROR] error writing public key into the bio" << RESET << endl;
        exit(1);
    }

    pubkey_size = BIO_get_mem_data(mbio, &buffer);
    memcpy(pubkey_buf, buffer, pubkey_size);

    if(pubkey_size < 0 || pubkey_size > UINT_MAX) {
        BIO_free(mbio);
        cout << RED << "[ERROR] error reading public key" << RESET << endl;
        exit(1);
    }

    BIO_free(mbio);

    return pubkey_size;
}

void CryptoOperation::deserializePublicKey(unsigned char* pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey){
    BIO *mbio;

    mbio = BIO_new(BIO_s_mem());

    if(!mbio) {
        cout << RED << "[ERROR] error creating the bio" << RESET << endl;
        exit(1);
    }

    if(BIO_write(mbio,pubkey_buf,pubkey_size) <= 0){
        cout << RED << "[ERROR] error writing the public key into the bio" << RESET << endl;
        exit(1);
    }

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
    if(!pctx) {
        cout << RED << "[ERROR] error creating the context" << RESET << endl;
        exit(1);
    }

    if( EVP_PKEY_paramgen_init(pctx) < 1 ) {
        cout << RED << "[ERROR] error during the initialization parameters" << RESET << endl;
        exit(1);
    }

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);

    if( EVP_PKEY_paramgen(pctx, &dh_params) < 1 ) {
        cout << RED << "[ERROR] error during the generation of parameters" << RESET << endl;
        exit(1);
    }

    EVP_PKEY_CTX_free(pctx);
}

void CryptoOperation::keyGeneration(EVP_PKEY *&my_prvkey){
    EVP_PKEY *dh_params = NULL;
    EVP_PKEY_CTX *ctx;

    buildParameters(dh_params);

    ctx = EVP_PKEY_CTX_new(dh_params,NULL);
    if(!ctx){
        cout << RED << "[ERROR] error creating the context" << RESET << endl;
        exit(1);
    }

    try
    {
        if(EVP_PKEY_keygen_init(ctx) < 1) {
            cout << RED << "[ERROR] error during the initialization context" << RESET << endl;
            exit(1);
        }

        if(EVP_PKEY_keygen(ctx, &my_prvkey) < 1){
            cout << RED << "[ERROR] error during the initialization parameters" << RESET << endl;
            exit(1);
        }

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
        cout << RED << "[ERROR] error allocating buffer" << RESET << endl;
            exit(1);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cout << RED << "[ERROR] error during the initialization context" << RESET << endl;
        exit(1);
    }

    try {
        if(EVP_SignInit(ctx, EVP_sha256()) != 1) {
            cout << RED << "[ERROR] error during the initialization sign" << RESET << endl;
            exit(1);
        }
        if(EVP_SignUpdate(ctx, message, messageLen) != 1) {
            cout << RED << "[ERROR] error updating sign" << RESET << endl;
            exit(1);
        }
        if(EVP_SignFinal(ctx, signature, &signLen, prvKey) != 1){
            cout << RED << "[ERROR] error finalizing sign" << RESET << endl;
            exit(1);
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
        cout << RED << "[ERROR] error creating the context" << RESET << endl;
        exit(1);
    }

    try {
        if(EVP_VerifyInit(ctx, EVP_sha256()) != 1){
            cout << RED << "[ERROR] error during the initialization of the verification" << RESET << endl;
            exit(1);
        }
        if(EVP_VerifyUpdate(ctx, message, messageLen) != 1) {
            cout << RED << "[ERROR] error during the signature verification" << RESET << endl;
            exit(1);
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

unsigned int CryptoOperation::encryptMessage(unsigned char* session_key, unsigned char* iv, unsigned char *msg, unsigned int msg_len, vector<unsigned char> &buffer) {
    unsigned char *ciphertext;
    unsigned char tag[constants::TAG_LEN];
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned int finalSize = 0;
    unsigned int start = 0;
    int len = 0;
    int ciphr_len = 0;

    // if( msg_len > (UINT_MAX - 2*TAG_SIZE + IV_SIZE + sizeof(uint16_t)) )
    //     throw runtime_error("Message too big.");

    finalSize = msg_len + 2*constants::TAG_LEN + constants::IV_LEN + sizeof(char);

    if(finalSize > constants::MAX_MESSAGE_SIZE) {
        cout << RED << "[ERROR] message too big" << RESET << endl;
        exit(1);
    }

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        cout << RED << "[ERROR] error during the creation of the context" << RESET << endl;
        exit(1);
    }
    
    ciphertext = new (nothrow) unsigned char[msg_len + constants::TAG_LEN];

    if(!ciphertext){
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    try {

        if(EVP_EncryptInit(ctx, EVP_aes_128_gcm(), session_key, iv) != 1){
            cout << RED << "[ERROR] error during the initialization of the context" << RESET << endl;
            exit(1);
        }
            
        // AAD: Insert the counter
        if(EVP_EncryptUpdate(ctx, NULL, &len, iv, constants::IV_LEN) != 1){
            cout << RED << "[ERROR] error during the encryption of the message" << RESET << endl;
            exit(1);
        }
            
        if(EVP_EncryptUpdate(ctx, ciphertext, &len, msg, msg_len) != 1){
            cout << RED << "[ERROR] error during the encryption of the message" << RESET << endl;
            exit(1);
        }
        ciphr_len = len;

        if(EVP_EncryptFinal(ctx, ciphertext + len, &len) != 1){
            cout << RED << "[ERROR] error finalizaing the encryption" << RESET << endl;
            exit(1);
        }
        ciphr_len += len;

        //Get the tag
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, constants::TAG_LEN, tag) != 1){
            cout << RED << "[ERROR] error getting the tag" << RESET << endl;
            exit(1);
        }
        
        if(ciphr_len < 0){
            cout << RED << "[ERROR] error in the encryption" << RESET << endl;
            exit(1);
        }
        
        // if(ciphr_len > UINT_MAX - IV_SIZE - TAG_SIZE - sizeof(uint16_t))
        //    throw runtime_error("An error occurred, ciphertext length too big.");
        
        buffer.resize(finalSize);

        memcpy(buffer.data() + start, &msg[0], sizeof(char));
        start +=sizeof(char);

        memcpy(buffer.data() + start, iv, constants::IV_LEN);
        start += constants::IV_LEN;

        memcpy(buffer.data() + start, ciphertext, ciphr_len);
        start += ciphr_len;

        memcpy(buffer.data() + start, tag, constants::TAG_LEN);
        start += constants::TAG_LEN;

    } catch(const exception& e) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return start;
}

unsigned int CryptoOperation::decryptMessage(unsigned char* session_key, unsigned char* iv, unsigned char *msg, unsigned int msg_len, vector<unsigned char> &buffer) {
    unsigned char recv_iv[constants::IV_LEN];
    unsigned char recv_tag[constants::TAG_LEN];
    unsigned char *ciphr_msg;
    unsigned char *tempBuffer;
    EVP_CIPHER_CTX *ctx;
    unsigned int ciphr_len = 0;
    int ret = 0;
    int len = 0;
    unsigned int pl_len = 0;

    if (msg_len < (constants::IV_LEN + constants::TAG_LEN)){
        cout << RED << "[ERROR] message length not valid " << RESET << endl;
        exit(1);
    }
    
    if(msg_len > constants::MAX_MESSAGE_SIZE){
        cout << RED << "[ERROR] message too big " << RESET << endl;
        exit(1);
    }

    ciphr_len = msg_len - constants::IV_LEN - constants::TAG_LEN - sizeof(char);
    ciphr_msg = new (nothrow) unsigned char[ciphr_len];

    if(!ciphr_msg){
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    tempBuffer = new (nothrow) unsigned char[ciphr_len];
    if(!tempBuffer){
        cout << RED << "[ERROR] malloc error" << RESET << endl;
        exit(1);
    }

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        delete[] ciphr_msg;
        cout << RED << "[ERROR] error creating the context" << RESET << endl;
        exit(1);
    } 

    try {
        memcpy(recv_iv, msg + sizeof(char), constants::IV_LEN);

        memcpy(ciphr_msg, msg + constants::IV_LEN + sizeof(char), ciphr_len);

        memcpy(recv_tag, msg + ciphr_len + constants::IV_LEN + sizeof(char), constants::TAG_LEN);

        if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), session_key, recv_iv)){
            cout << RED << "[ERROR] error during the initialization of decryption" << RESET << endl;
            exit(1);
        }
        
        if(!EVP_DecryptUpdate(ctx, NULL, &len, recv_iv, constants::IV_LEN)){
            cout << RED << "[ERROR] error while decrypting the message " << RESET << endl;
            exit(1);
        }

        if(!EVP_DecryptUpdate(ctx, tempBuffer, &len, ciphr_msg, ciphr_len)){
            cout << RED << "[ERROR] error while decrypting the message " << RESET << endl;
            exit(1);
        }
        pl_len = len;
        
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, constants::TAG_LEN, recv_tag)){
            cout << RED << "[ERROR] error while setting the tag " << RESET << endl;
            exit(1);
        }
        
        ret = EVP_DecryptFinal(ctx, tempBuffer + len, &len);

        buffer.resize(pl_len);
        memcpy(buffer.data(), tempBuffer, pl_len);
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
    } else{
        cout << RED << "[ERROR] error while decrypting the message " << RESET << endl;
        exit(1);
    }
    
    if (pl_len < 0 || pl_len > UINT_MAX){
        cout << RED << "[ERROR] error while decrypting the message " << RESET << endl;
        exit(1);
    }

    return pl_len;
}

void CryptoOperation::computeHash(unsigned char *msg, unsigned int msg_size, unsigned char *digest) {
    unsigned int len;
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    if(!ctx){
        cout << RED << "[ERROR] error while creating the context " << RESET << endl;
        exit(1);
    }

    try {
        if(EVP_DigestInit(ctx, EVP_sha256()) < 1){
            cout << RED << "[ERROR] error during the initialization the digest " << RESET << endl;
            exit(1);
        }

        if(EVP_DigestUpdate(ctx, msg, msg_size) < 1){
            cout << RED << "[ERROR] error during the creation the digest " << RESET << endl;
            exit(1);
        }
        if(EVP_DigestFinal(ctx, digest, &len) < 1){
            cout << RED << "[ERROR] error during the conclusion the digest " << RESET << endl;
            exit(1);
        }
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

    if(!peer_pubkey){
            cout << RED << "[ERROR] error reading the public key " << RESET << endl;
            exit(1);
        }

    ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    if(!ctx_drv){
            cout << RED << "[ERROR] error during the creation the context " << RESET << endl;
            exit(1);
        }

    if(EVP_PKEY_derive_init(ctx_drv) < 1) {
        EVP_PKEY_CTX_free(ctx_drv);
        cout << RED << "[ERROR] error during the initialization the context " << RESET << endl;
        exit(1);
    } 

    if(EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        cout << RED << "[ERROR] error setting the peer public key" << RESET << endl;
        exit(1);
        
    }  
     
    if(EVP_PKEY_derive(ctx_drv, NULL, &secretlen) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        cout << RED << "[ERROR] error deriving the secret " << RESET << endl;
        exit(1);
    }

    secret = (unsigned char*)OPENSSL_malloc(secretlen);
    if(!secret) {
        EVP_PKEY_CTX_free(ctx_drv);
        cout << RED << "[ERROR] openssl malloc error " << RESET << endl;
        exit(1);
    }

    if(EVP_PKEY_derive(ctx_drv, secret, &secretlen) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        OPENSSL_free(secret);
        cout << RED << "[ERROR] error deriving the secret " << RESET << endl;
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx_drv);
    computeHash(secret, secretlen, buffer);
    OPENSSL_free(secret);
}
