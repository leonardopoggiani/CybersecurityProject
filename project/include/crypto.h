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
    void generateNonce(unsigned char* nonce);
};
