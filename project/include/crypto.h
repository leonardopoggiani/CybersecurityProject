#include <iostream>
#include <string>
#include <array>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "constants.h"

using namespace std;

class CryptoOperation {

    public:
    void generateNonce(unsigned char* nonce);

    //CERTIFICATES
    void loadCRL(X509_CRL*& crl);
    void loadCertificate(X509*& cert, string path);
    unsigned int serializeCertificate(X509* cert, unsigned char* cert_buf);
    void deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff);
    bool verifyCertificate(X509* cert_to_verify);

    //KEYS
    void readPrivateKey(string usr, string pwd, EVP_PKEY *&prvKey);
    void readPrivateKey(EVP_PKEY *&prvKey);
    void readPublicKey(string user, EVP_PKEY *&pubKey);

   // Public Key handling
    unsigned int serializePublicKey(EVP_PKEY *pub_key, unsigned char *pubkey_buf);
    void deserializePublicKey(unsigned char *pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey);
    void getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey);
    
};
