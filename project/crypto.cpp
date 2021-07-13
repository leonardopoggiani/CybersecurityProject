#include "include/crypto.h"

using namespace std;

//Message Digest for digital signature and hash
const EVP_MD* md = EVP_sha256();

void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

void CryptoOperation::generateNonce(unsigned char* nonce) {
    if(RAND_poll() != 1)
        throw std::runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(nonce, constants::NONCE_SIZE) != 1)
        throw std::runtime_error("An error occurred in RAND_bytes.");
        
    cout << "nonce generated" << endl;
}

//CERTIFICATES

void CryptoOperation::loadCertificate(X509*& cert, string path){
    
    string path_str = "certificates/" + path + ".pem";
    FILE *file = fopen(path_str.c_str(),"r");
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

void CryptoOperation::loadCRL(X509_CRL*& crl, string path){
    FILE* file = fopen(path.c_str(), "r");

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

    loadCertificate(ca_cert, constants::CA_CERT_PATH);
    loadCRL(crl, constants::CRL_PATH);

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
    file = fopen("./keys/server_prv_key.pem", "r");
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
    path = "./keys/" + usr + "_prvkey.pem";
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


// DH parameters

void CryptoOperation::buildParameters(EVP_PKEY *&dh_params) {
    DH *temp;
    dh_params = EVP_PKEY_new();

    if(!dh_params)
        throw runtime_error("An error occurred during the allocation of parameters.");

    temp = DH_get_2048_224();

    if(EVP_PKEY_set1_DH(dh_params,temp) == 0){
        DH_free(temp);
        throw runtime_error("An error occurred during the generation of parameters.");
    }

    DH_free(temp);
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

    return signLen;
}

bool CryptoOperation::digsign_verify(unsigned char *signature, unsigned int signLen, unsigned char *message, unsigned int messageLen, EVP_PKEY *pubKey) {
    int ret;
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
