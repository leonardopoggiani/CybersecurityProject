
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <fstream>
#include <regex>
#include "constants.h"

class Session{
	private:

		unsigned char* session_key;
		unsigned char* iv;

	public:

	Session() {
		session_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
		iv = (unsigned char*)malloc(constants::IV_LEN);
	}

	~Session() {
		free(session_key);
		free(iv);
	}

	unsigned char* get_session_key() { return session_key; }
	unsigned char* get_iv() { return iv; }

		
};
