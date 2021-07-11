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
    
    std::string path_str = "certificates/" + path + ".pem";
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

void CryptoOperation::loadCRL(X509_CRL*& crl){
    FILE* file = fopen("./certificates/crl_cert.pem", "r");

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

unsigned int CryptoOperation::sign(unsigned char *message, unsigned int messageLen, unsigned char *buffer, EVP_PKEY *prvKey) {

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

        memcpy(buffer, signature, signLen);
        delete[] signature;
        EVP_MD_CTX_free(ctx);

    } catch(const exception& e) {
        delete[] signature;
        EVP_MD_CTX_free(ctx);
        throw;
    }

    return signLen;
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


//Digital Signature Sign/Verify
unsigned int CryptoOperation::digsign_sign(EVP_PKEY* prvkey, unsigned char* clear_buf, unsigned int clear_size, unsigned char* output_buffer){
	int ret; // used for return values

	if(clear_size > constants::MAX_MESSAGE_SIZE){ 
        cerr << "digsign_sign: message too big(invalid)\n"; 
        exit(1); 
    }

	// create the signature context:
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ 
        cerr << "digsign_sign: EVP_MD_CTX_new returned NULL\n"; 
        exit(1); 
    }

	ret = EVP_SignInit(md_ctx, md);
	if(ret == 0){ 
        cerr << "digsign_sign: EVP_SignInit returned " << ret << "\n"; 
        exit(1); 
    }

	ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
	if(ret == 0){ 
        cerr << "digsign_sign: EVP_SignUpdate returned " << ret << "\n"; 
        exit(1); 
    }

	unsigned int sgnt_size = 0;
    int signed_size = 0;
	unsigned char* signature_buffer = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
	if(!signature_buffer){
        cerr<<"Malloc Error";
        exit(1);
    
    }
	ret = EVP_SignFinal(md_ctx, signature_buffer, &sgnt_size, prvkey);
	if(ret == 0){ 
        cerr << "digsign_sign: EVP_SignFinal returned " << ret << "\n"; 
        exit(1); 
    }

	unsigned int written = 0;	
    cout << "clear_size: " << clear_size << "sgnt_size: " << sgnt_size << endl;

    // clear_message | signature_size | signature

    memcpy(&(output_buffer[written]), clear_buf, clear_size);
	written += clear_size;

    cout << "sign size: " << sgnt_size << ", clear size: " << clear_size << endl;
    signed_size = sgnt_size - clear_size;
    cout << "size of the signature " << signed_size << endl;
    
	memcpy(&(output_buffer[written]), &signed_size, sizeof(unsigned int));
	written += sizeof(unsigned int);

	memcpy(&(output_buffer[written]), signature_buffer, signed_size);
	written += signed_size;

	EVP_MD_CTX_free(md_ctx);
	return sgnt_size;
}

//da modificare perchè la firma adesso sta alla fine
int CryptoOperation::digsign_verify(EVP_PKEY* peer_pubkey, unsigned char* input_buffer, unsigned int input_size, unsigned char* output_buffer,  unsigned int dim_msg, unsigned int sgnt_size){
	int ret;
    
    unsigned int read = sizeof(unsigned int);

    cout << "input_size: " << input_size << ",sizeof(unsigned int): " << read << ",sgnt_size: " << sgnt_size << endl;

	// if(input_size <= sizeof(unsigned int) + sgnt_size){ 
    //    cerr << " digsign_verify: empty or invalid message \n"; \
    //    exit(1); 
    //}

	unsigned char* signature_buffer = (unsigned char*)malloc(sgnt_size);

	if(!signature_buffer){
        cerr<<"Malloc Error";
        exit(1);
    }

	memcpy(signature_buffer, input_buffer + (input_size - sgnt_size), sgnt_size);
	read += sgnt_size;

	// create the signature context:
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ 
        cerr << "Error: EVP_MD_CTX_new returned NULL\n"; 
        exit(1); 
    }

	// verify the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){ 
        cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; 
        exit(1); 
    }

	ret = EVP_VerifyUpdate(md_ctx, input_buffer, (input_size - sgnt_size));  
	if(ret == 0){ 
        cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; 
        exit(1); 
    }

	ret = EVP_VerifyFinal(md_ctx, signature_buffer, sgnt_size, peer_pubkey);
	if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
	    cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
	    ERR_error_string_n(ERR_get_error(),(char *)output_buffer,constants::MAX_MESSAGE_SIZE);  
	    cerr << output_buffer <<"\n";
	    exit(1);
	}else if(ret == 0){      
        cerr << "Error: Invalid signature!\n"; 
        return -1;
	}

	// deallocate data:
	EVP_MD_CTX_free(md_ctx);

	return input_size - read;
}
