// snippet di codice utile riutilizzabili

/*** START FILE ***/
#include <iostream>
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

/*** GENERAL INPUT CONTROL ***/
cout << "Please, type the name of the file containing my data: ";
getline(cin, filename);
if(!cin) { cerr << "Error during input\n"; exit(1); }


/*** GET FILE SIZE ***/
fseek(file, 0, SEEK_END);
long int file_size = ftell(file);
fseek(file, 0, SEEK_SET);

/*** OVERFLOW CONTROL ***/
if(buffer_len > INT_MAX) { cerr << "Error: integer overflow (len too big?)\n"; exit(1); }

/*** DELETE PLAINTEXT ***/
#pragma optimize("", off)
memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
free(clear_buf);

/*** GENERAL VARIABLES ***/
const EVP_CIPHER* cipher = EVP_aes_128_cbc();
int encrypted_key_len = EVP_PKEY_size(pubkey);
int iv_len = EVP_CIPHER_iv_length(cipher);
int block_size = EVP_CIPHER_block_size(cipher);

// create the envelope context
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }

// allocate buffers for encrypted key and IV:
unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(cipher));
if(!encrypted_key || !iv) { cerr << "Error: malloc returned NULL (encrypted key too big?)\n"; exit(1); }

// check for possible integer overflow in (clear_size + block_size)
// (possible if the plaintext is too big, assume non-negative clear_size and block_size):
if(clear_size > INT_MAX - block_size) { cerr <<"Error: integer overflow (file too big?)\n"; exit(1); }

// allocate a buffer for the ciphertext:
int enc_buffer_size = clear_size + block_size;
unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
if(!cphr_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

// deallocate buffers:
free(cphr_buf);
free(encrypted_key);
free(iv);
