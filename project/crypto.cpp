#include "crypto.h"

using namespace std;

void generateNonce(unsigned char* nonce) {
    if(RAND_poll() != 1)
        throw runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(nonce, NONCE_SIZE) != 1)
        throw runtime_error("An error occurred in RAND_bytes.");
}