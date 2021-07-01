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
class Crypto {

    void generateNonce(unsigned char* nonce);
    // Certificates
    void loadCRL(X509_CRL*& crl);
    void loadCertificate(X509*& cert, string path);
    unsigned int serializeCertificate(X509* cert, unsigned char* cert_buf);
    void deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff);
    bool verifyCertificate(X509* cert_to_verify);
};
