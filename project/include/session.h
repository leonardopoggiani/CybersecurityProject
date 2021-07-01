
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

class Session{
	private:
		int fd;
		uint32_t counterpart_nonce;
		EVP_PKEY* counterpart_pubkey;
		char* key_encr;
		char* key_auth;
		uint32_t my_nonce;

	public:
		Session(unsigned int fd);
		~Session();
		
		// Restituisce il numero di sequenza della controparte
		uint32_t get_counterpart_nonce();
		// Restituisce la chiave pubblica della controparte
		EVP_PKEY* get_counterpart_pubkey();
		// Restituisce il numero del file descriptor
		unsigned int get_fd();
		// Scrive in buffer il valore di IV
		bool get_iv(char* buffer, size_t size);
		// Restituisce il mio numero di sequenza
		uint32_t get_my_nonce();
		// Restituisce la chiave simmetrica di autenticazione
		int get_key_auth(char *buffer);
		// Restituisce la chiave simmetrica di cifratura
		int get_key_encr(char *buffer);
		// Inizializza iv, key_encr e key_auth con byte pseudocasuali
		int initialize(const EVP_CIPHER *type_encr, const EVP_MD *type_auth);
		// Salva il numero di sequenza della controparte
		void set_counterpart_nonce(uint32_t nonce);
		// Salva la chiave pubblica del server
		void set_counterpart_pubkey(EVP_PKEY *pubkey);
		// Salva il valore IV
		int set_iv(const EVP_CIPHER *type, char* iv_buffer);
		// Salva la chiave simmetrica di autenticazione
		int set_key_auth(const EVP_MD *type, char* key);
		// Salva la chiave simmetrica di cifratura
		int set_key_encr(const EVP_CIPHER *type, char* key);
};
