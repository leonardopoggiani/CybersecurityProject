#include "include/session.h"

/*Session::Session(unsigned int fd){
	this->fd = fd;
	key_auth = NULL;
	key_encr = NULL;
	//char buffer[sizeof(my_nonce)];
	if(get_random((char*)&my_nonce, sizeof(my_nonce)) < 0)
		my_nonce = 1;
	if(my_nonce > (UINT32_MAX / 2))
		my_nonce = my_nonce - (UINT32_MAX / 2);
	
	counterpart_nonce = 0;
}

Session::~Session(){
	if(key_encr != NULL) {
		memset(key_encr, 0, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
		delete[] key_encr;
	}	
	if(key_auth != NULL) {
		memset(key_auth, 0, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
		delete[] key_auth;
	}
	if(counterpart_pubkey != NULL)
		EVP_PKEY_free(counterpart_pubkey);
}*/