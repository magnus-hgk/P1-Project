#ifndef KEYEXCHANGE_H
#define KEYEXCHANGE_H

#include <winsock2.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Function prototypes
char* start_key_exchange();
char* run_server();
char* run_client();
void encrypt_message(char* secret);
void decrypt_message(char* secret);
void send_encrypted_message(char* secret);
void receive_encrypted_message(char* secret);
char* create_key_from_password();

void handle_error(const char *msg);

// RSA and KDF functions
EVP_PKEY* generate_rsa_key();
void print_rsa_fingerprint(EVP_PKEY* pkey);
uint8_t* sign_data(EVP_PKEY* pkey, const uint8_t* data, int data_len, unsigned int* sig_len);
int verify_signature(EVP_PKEY* pkey, const uint8_t* data, int data_len, uint8_t* sig, unsigned int sig_len);
void derive_key(const char* shared_secret, uint8_t* derived_key);
void send_rsa_key(SOCKET sock, EVP_PKEY* pkey);
EVP_PKEY* receive_rsa_key(SOCKET sock);

#endif // KEYEXCHANGE_H
