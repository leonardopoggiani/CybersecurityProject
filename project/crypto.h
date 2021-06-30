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
#include "costants.h"

class Crypto {
    void generateNonce(unsigned char* nonce) {
        if(RAND_poll() != 1)
            throw std::runtime_error("An error occurred in RAND_poll."); 
        if(RAND_bytes(nonce, NONCE_SIZE) != 1)
            throw std::runtime_error("An error occurred in RAND_bytes.");
    }
};
