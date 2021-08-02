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
#include "connection.h"

using namespace std;

class CryptoOperation {

    public:

        void generateNonce(unsigned char* nonce);

        //CERTIFICATES
        void loadCRL(X509_CRL*& crl);
        void loadCertificate(X509*& cert, string path);
        unsigned int serializeCertificate(X509* cert, unsigned char* cert_buf);
        void deserializeCertificate(int cert_len, unsigned char* cert_buff, X509*& buff);
        bool verifyCertificate(X509* cert_to_verify);

        //KEYS
        void readPrivateKey(string usr, string pwd, EVP_PKEY *&prvKey);
        void readPrivateKey(EVP_PKEY *&prvKey);
        void readPublicKey(string user, EVP_PKEY *&pubKey);

        // Public Key handling
        unsigned int serializePublicKey(EVP_PKEY *pub_key, unsigned char *pubkey_buf);
        void deserializePublicKey(unsigned char *pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey);
        void getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey);

        // digital signature
        bool digsign_verify(unsigned char *signature, unsigned int signLen, unsigned char *message, unsigned int messageLen, EVP_PKEY *pubKey);
        unsigned int digsign_sign(unsigned char* clear_buf, unsigned int clear_size, unsigned char* output_buffer, EVP_PKEY* prvkey);

        // encryption and decryption
        unsigned int encryptMessage(unsigned char* key, unsigned char* iv, unsigned char *msg, unsigned int msg_len, vector<unsigned char> &buffer);
        unsigned int decryptMessage(unsigned char* key, unsigned char* iv, unsigned char *msg, unsigned int msg_len, vector<unsigned char> &buffer);

        void buildParameters(EVP_PKEY *&dh_params);
        void keyGeneration(EVP_PKEY *&my_prvkey);
        unsigned int sign(unsigned char *message, unsigned int messageLen, unsigned char *buffer, EVP_PKEY *prvKey);
        void secretDerivation(EVP_PKEY *my_prvkey, EVP_PKEY *peer_pubkey, unsigned char *buffer);
        void computeHash(unsigned char *msg, unsigned int msg_size, unsigned char *digest);
        static DH* get_dh2048(void);
};
