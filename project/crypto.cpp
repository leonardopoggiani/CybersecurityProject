#include "include/crypto.h"

using namespace std;

void Crypto::generateNonce(unsigned char* nonce) {
    if(RAND_poll() != 1)
        throw std::runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(nonce, constants::NONCE_SIZE) != 1)
        throw std::runtime_error("An error occurred in RAND_bytes.");
}