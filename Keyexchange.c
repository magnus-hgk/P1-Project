#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Keyexchange.h"
#include "aes.h"
#include "base64.h"

extern void encrypt(aes_context *context, char *plain_text, uint8_t *hex_text);
extern void decrypt(aes_context *context, uint8_t *encrypted_text, int encrypted_len, uint8_t *plain_text);

#pragma comment(lib, "ws2_32.lib")

#define PORT 8888
#define BUFFER_SIZE 4096
#define MAX_PASSWORD_LENGTH 100
#define MAX_MESSAGE_LENGTH 4096
SOCKET g_socket = INVALID_SOCKET;


// Prototypes of later functions
void send_bn(SOCKET sock, BIGNUM *bn);
BIGNUM* receive_bn(SOCKET sock);
void encryption(char* secret);
void decryption(char* secret);
void send_encrypted_message(char* secret);
void receive_encrypted_message(char* secret);
char* create_key_from_password();


char* start_key_exchange(){
    // Assign variables
    WSADATA wsa;
    char choice;
    char* secret = NULL;

    // Start Winsock
    printf("Initializing WinSock.. \n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d\n", WSAGetLastError());
        return NULL;
    }
    printf("Winsock started..\n");
    //Print mode selector
    printf("Select mode\n");

    printf("s - Server (other person will connect to you)\n ");
    printf("c - Client \n");
    printf("Enter choice: ");
    scanf(" %c", &choice);
    // Choice result tree
    if (choice == 's' || choice == 'S'){
            secret = run_server();
    } else if (choice == 'c' || choice == 'C'){
        secret = run_client();
    }else {
        printf("Invalid choice.... \n");
        WSACleanup();
        return NULL;
    }

    return secret;
}

// Error printer function
void handle_error(const char *msg){
    printf("Error: %s. Code: %d\n",msg, WSAGetLastError());
    ERR_print_errors_fp(stderr);//Openssl errors
    WSACleanup();
    exit(1);
}

//Big_num sender function
void send_bn(SOCKET sock, BIGNUM *bn){
    char *hex_str = BN_bn2hex(bn);
    if(hex_str == NULL){
        handle_error("Failed to convert BN to hex");
    }

    int len = strlen(hex_str);
    if (send(sock,(char*)&len,sizeof(int),0) == SOCKET_ERROR){
        handle_error("Send lenght failed");
    }

    if (send(sock,hex_str,len,0) == SOCKET_ERROR){
        handle_error("Send BN failed");
    }
    OPENSSL_free(hex_str);
}

//Receive Big Number from socket
BIGNUM* receive_bn(SOCKET sock){
    int len;
    // first receive length
    if (recv(sock, (char*)&len, sizeof(int), 0) == SOCKET_ERROR){
        handle_error("Receiving length failed");
    }

    char* buffer = (char*)malloc(len+1);
    if (!buffer){
        handle_error("Memory allocation failed");
    }
    //now we can receive the hex string
    int received = 0;
    while (received < len) {
        int ret = recv(sock, buffer + received, len - received, 0);
        if (ret == SOCKET_ERROR || ret == 0) {
            handle_error("Receive BN failed");
        }
        received += ret;
    }

    BIGNUM *bn = NULL;
    if (BN_hex2bn(&bn, buffer) == 0){
        handle_error("Failed to convert hex to big number");
    }

    free(buffer);
    return bn;
}

char* run_server(){
    // initialise variables
    SOCKET server_socket, client_socket;
    struct sockaddr_in server, client;
    int c;
    
    // create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET){
        handle_error("Failed to create Socket");
    }

    // fill in stucture with socket address
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT); // convert the port data from host byte order to network byte order


    // Bind
    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR){
        handle_error("Bind failed");
    }

    // listen on socket
    listen(server_socket,3);

    //Display server IP's
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0){
        struct hostent *he = gethostbyname(hostname);
        if (he != NULL){
            printf("Server is running on\n");
            struct in_addr ** addr_list = (struct in_addr **) he ->h_addr_list;
            for (int i = 0; addr_list[i] != NULL; i++) {
                printf(" - %s\n", inet_ntoa(*addr_list[i]));
            }
        }
    }

    printf("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_in);
    client_socket = accept(server_socket, (struct sockaddr *)&client, &c);
    if(client_socket == INVALID_SOCKET){
        handle_error("Accept failed");
    }
    printf("Connection accepted\n");


    // ---RSA---
    printf("Generating RSA keypair\n");
    EVP_PKEY *rsa_key = generate_rsa_key();
    printf("My RSA Fingerprint: \n");
    print_rsa_fingerprint(rsa_key);

    printf("Exchanging RSA Keys... \n");
    send_rsa_key(client_socket, rsa_key);
    EVP_PKEY *client_rsa_key = receive_rsa_key(client_socket);
    printf("Recieved Client RSA Key. Fingerprint: \n");
    print_rsa_fingerprint(client_rsa_key);

    //Confirmation 
    char confirm;
    printf("Do the fingerprints match what your partner is telling you? (y/n): ");
    scanf(" %c",&confirm);
    if (confirm != 'y' && confirm != 'Y'){
        printf("Key verification failed by user. Aborting  \n");
        WSACleanup();
        exit(1);
    }

    // --- Diffie-Hellmann Server side

    // Initialise OpenSSL variables
    BIGNUM *P = BN_new(); // Prime
    BIGNUM *G = BN_new(); // Generator
    BIGNUM *a = BN_new(); // Private Key
    BIGNUM *A = BN_new(); // Public Key
    BIGNUM *s = BN_new(); // Shared secret
    BN_CTX *ctx = BN_CTX_new();


    // Generate P ang G
    printf("Generating 2048-bit prime number P (this may take a moment)...\n");
    if (!BN_generate_prime_ex(P, 2048, 0, NULL, NULL, NULL)) {
        handle_error("Failed to generate prime");
    }

    // G is hardcoded to 2 here for simplicity in this demo
    BN_set_word(G, 2);

    printf("Generated P and G\n");

    // Send P and G to client
    printf("Sending P and G to client...\n");
    send_bn(client_socket, P);
    send_bn(client_socket, G);

    // Generate private key 'a'
    BN_rand(a, 2048, -1, 0);

    // Calculate public key A = G^a mod P
    BN_mod_exp(A, G, a, P, ctx);

    // Send A to client AND Sign it
    printf("Sending public key A to client... \n");
    send_bn(client_socket, A);

    // Sign A
    char *A_hex = BN_bn2hex(A);
    unsigned int sig_len;
    uint8_t *sig = sign_data(rsa_key, (uint8_t*)A_hex, strlen(A_hex), &sig_len);
    if (send(client_socket, (char*)&sig_len, sizeof(int), 0) == SOCKET_ERROR){
        handle_error("send sig len failed");
    }
    if (send(client_socket, (char*)sig, sig_len, 0) == SOCKET_ERROR){
        handle_error("send sig failed...");
    }
    OPENSSL_free(A_hex);
    free(sig);

    // Receive Client Public Key and verify signature
    printf("Waiting for Clients Public Key B... \n");
    BIGNUM *B = receive_bn(client_socket);

    //Receive Signature
    unsigned int client_sig_len;
    if (recv(client_socket, (char*)&client_sig_len, sizeof(int), 0) <= 0){
        handle_error("Failed to receieve signature length");
    }
    uint8_t *client_sig = (uint8_t*)malloc(client_sig_len);
    int total_rec = 0;
    while(total_rec < client_sig_len){
        int r = recv(client_socket, (char*)client_sig + total_rec, client_sig_len - total_rec, 0);
        if (r <= 0) {handle_error("Failed to recieve signature");}
        total_rec += r;
    }


    // Verify
    char *B_hex = BN_bn2hex(B);
    if (verify_signature(client_rsa_key, (uint8_t*)B_hex, strlen(B_hex), client_sig, client_sig_len) != 1) {
        printf("ERROR: Signature verification failed! Potential Man in the middle attack \n");
        WSACleanup();
        exit(1);
    } else {
        printf("Signature verified Client Identity confirmed \n");
    }
    OPENSSL_free(B_hex);
    free(client_sig);

    // Calculate shared secret s =B^a mod P
    BN_mod_exp(s, B, a, P, ctx);

    printf("\n--------------------------------------------------\n");
    printf("Shared Secret Established!\n");
    char *secret_str = BN_bn2hex(s);
    printf("Secret: %s\n", secret_str);
    printf("--------------------------------------------------\n");

    // Derive Key
    uint8_t derived_key[32];
    derive_key(secret_str,derived_key);

    // Convert derived key to hex string for return
    char *final_key_hex = (char*)OPENSSL_malloc(65);
    if (!final_key_hex){
        handle_error("Memory allocation failed");
    }
    for (int i = 0; i < 32; i++){
        sprintf(final_key_hex + (i * 2), "%02X", derived_key[i]);
    }
    final_key_hex[64] = '\0';

    OPENSSL_free(secret_str); // free up the memory from the raw DH secret


    //cleanup
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(client_rsa_key);
    BN_free(P); BN_free(G); BN_free(a); BN_free(A); BN_free(B); BN_free(s);
    BN_CTX_free(ctx);
    g_socket = client_socket;
    closesocket(server_socket);

    return final_key_hex;

}

char* run_client(){
    SOCKET sock;
    struct sockaddr_in server;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET){
        handle_error("Could not create socket");
    }

    char ip_address[100];
    printf("Enter Server IP Address (e.g. 127.0.0.1): ");
    scanf("%99s", ip_address);

    server.sin_addr.s_addr = inet_addr(ip_address);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    //connect
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0){
        handle_error("Error when trying to connect");
    }
    printf("Connected to server\n");

    // --- RSA Setup ---
    printf("Generating RSA Keypair...\n");
    EVP_PKEY *rsa_key = generate_rsa_key();
    printf("My RSA Key Fingerprint:\n");
    print_rsa_fingerprint(rsa_key);

    printf("Exchanging RSA Keys...\n");
    EVP_PKEY *server_rsa_key = receive_rsa_key(sock);
    printf("Received Server RSA Key. Fingerprint:\n");
    print_rsa_fingerprint(server_rsa_key);
    send_rsa_key(sock, rsa_key);

    //Manual confirmation
    char confirm;
    printf("Do the fingerprints match what your partner is telling you? (y/n): ");
    scanf(" %c", &confirm);
    if (confirm != 'y' && confirm != 'Y'){
        printf("Fingerprint verification failed by user. Aborting. \n");
        WSACleanup();
        exit(1);
    }


    // --- Diffie-Helmman Client side ---

    // OpenSSL Variables
    BIGNUM *b = BN_new(); // Private Key
    BIGNUM *B = BN_new(); // Public Key
    BIGNUM *s = BN_new(); // Shared Secret
    BN_CTX *ctx = BN_CTX_new();


    // Receive P and G from Server
    printf("Receiving P and G from server... .\n");
    BIGNUM *P = receive_bn(sock);
    BIGNUM *G = receive_bn(sock);

    // Generate private key b
    BN_rand(b, 2048, -1, 0);

    // Caculate public key B = G^b mod P
    BN_mod_exp(B, G, b, P, ctx);

    // receive servers public key A and verify signature
    printf("Receiving Server's Public Key A... \n");
    BIGNUM *A = receive_bn(sock);

    // Receive Signature
    unsigned int server_sig_len;
    if (recv(sock, (char*)&server_sig_len, sizeof(int), 0) <= 0){
        handle_error("Failed to receive signature length");
    }
    uint8_t *server_sig = (uint8_t*)malloc(server_sig_len);
    int total_rec = 0;
    while (total_rec < server_sig_len){
        int r = recv(sock, (char*)server_sig + total_rec, server_sig_len -total_rec, 0);
        if (r <= 0) {
            handle_error("Failed to receive signature");
        }
        total_rec += r;
    }

    // Verify
    char *A_hex = BN_bn2hex(A);
    if (verify_signature(server_rsa_key, (uint8_t*)A_hex, strlen(A_hex), server_sig, server_sig_len) != 1){
        printf("ERROR: Signature verification failed! Potential man in the middle attack \n");
        WSACleanup();
        exit(1);  
    } else {
        printf("Signature verified. Server identity confirmed \n");
    }
    OPENSSL_free(A_hex);
    free(server_sig);

    // Send public key B to server and sign it
    printf("Sending public key B to server.... \n");
    send_bn(sock, B);

    //Sign B
    char *B_hex =BN_bn2hex(B);
    unsigned int sig_len;
    uint8_t *sig = sign_data(rsa_key, (uint8_t*)B_hex, strlen(B_hex), &sig_len);
    if (send(sock, (char*)&sig_len, sizeof(int), 0) == SOCKET_ERROR){
        handle_error("Failed to send length of signature");
    }
    if (send(sock,(char*)sig, sig_len, 0) == SOCKET_ERROR){
        handle_error("Failed to send Signature");
    }
    OPENSSL_free(B_hex);
    free(sig);

    // Calculate shared secret s A^b mod P
    BN_mod_exp(s, A, b, P, ctx);


    printf("\n--------------------------------------------------\n");
    printf("Shared Secret Established!\n");
    char *secret_str = BN_bn2hex(s);
    printf("Secret: %s\n", secret_str);
    printf("--------------------------------------------------\n");

    // Derive Key
    uint8_t derived_key[32];
    derive_key(secret_str, derived_key);

    // Convert derived Key to Hex for return
    char *final_key_hex = (char*)OPENSSL_malloc(65);
    if (!final_key_hex) {
        handle_error("memory allocation failed");
    }
    for (int i = 0; i < 32; i++){
        sprintf(final_key_hex + (i * 2), "%02X", derived_key[i]);
    }
    final_key_hex[64] = '\0';

    OPENSSL_free(secret_str); // Free the raw DH secret

    //cleanup
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(server_rsa_key);
    BN_free(P); BN_free(G); BN_free(b); BN_free(B); BN_free(A); BN_free(s);
    BN_CTX_free(ctx);
    g_socket =sock;

    return final_key_hex;
}


//Encrypt message goes here
void encrypt_message(char* secret){
    if (secret == NULL){
        printf("ERROR: no secret key established Please run Key exchange first \n");
        return;
    }
    printf("Encrypting message using key: %s \n", secret);
    encryption(secret);
}

void hexStringToBytes(const char *hex, uint8_t *bytes, int *len) {
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0) 
    {
        printf("Invalid hex key length.\n");
        exit(EXIT_FAILURE);
    }
    *len = hex_len / 2;
    for (int i = 0; i < *len; i++) 
    {
        unsigned int temp;
        sscanf(hex + 2 * i, "%2x", &temp);
        bytes[i] = (uint8_t)temp;
    }
}
//actual encryption function
void encryption(char* secret){
    aes_context context;
    uint8_t key[AES_256_KEY];
    
    // Parse hex secret to key bytes
    hexStringToBytes(secret, key, &context.key_len);
    setKey(&context, key);
    keySchedule(&context);

    char plain_text[MAX_MESSAGE_LENGTH];
    uint8_t hex_text[MAX_MESSAGE_LENGTH * 2]; // Buffer for encryption
    char base64_text[MAX_MESSAGE_LENGTH * 4];

    printf("Enter message to encrypt: ");
    scanf(" \n%[^\n]s", plain_text); 

    encrypt(&context, plain_text, hex_text);
    base64_encode(hex_text, context.length, base64_text);
    printf("Encrypted (Base64): %s\n", base64_text);
    
}

//actual decryption function
void decrypt_message(char* secret) {
    if (secret == NULL) {
        printf("Error: No shared secret established. Please run key exchange first.\n");
        return;
    }
    printf("Decrypting message using secret: %s\n", secret);
    
    aes_context context;
    uint8_t key[AES_256_KEY];

    hexStringToBytes(secret, key, &context.key_len);
    setKey(&context, key);
    keySchedule(&context);

    char input_text[MAX_MESSAGE_LENGTH * 4]; 
    uint8_t hex_text[MAX_MESSAGE_LENGTH * 2]; 

    printf("Input encrypted text (base64): ");
    scanf(" \n%[^\n]s", input_text);
    
    // FIX: Capture length
    int len = base64_decode(input_text, hex_text); 
    decrypt(&context, hex_text, len, hex_text); 
    // Null-terminate the string using the length calculated by decrypt
    hex_text[context.length] = '\0'; 
    printf("Decrypted Message: %s\n", hex_text);
}

//Send and receive message
void send_encrypted_message(char* secret){
    if (g_socket == INVALID_SOCKET){
        printf("Error: No socket established. Please run key exchange first.\n");
        return;
    }
    
    // Encryption Logic Copied here to avoid recursion/double-prompt
    aes_context context;
    uint8_t key[AES_256_KEY];
    hexStringToBytes(secret, key, &context.key_len);
    setKey(&context, key);
    keySchedule(&context);

    char plain_text[MAX_MESSAGE_LENGTH];
    uint8_t hex_text[MAX_MESSAGE_LENGTH * 2]; 
    char base64_text[MAX_MESSAGE_LENGTH * 4];

    printf("Enter message to send: ");
    scanf(" \n%[^\n]s", plain_text); 

    encrypt(&context, plain_text, hex_text);
    base64_encode(hex_text, context.length, base64_text);
    
    // Send Logic
    int message_len = strlen(base64_text);
    if(send(g_socket, (char*)&message_len, sizeof(int), 0) == SOCKET_ERROR){
        handle_error("Failed to send message length");
    }
    if(send(g_socket, base64_text, message_len, 0) == SOCKET_ERROR){
        handle_error("Failed to send message");   
    }
    printf("Message sent: %s\n", base64_text);
}

void receive_encrypted_message(char* secret){
    if (g_socket == INVALID_SOCKET){
        printf("Error: No socket established. Please run key exchange first.\n");
        return;
    }
    if (secret == NULL){
        printf("Error: No shared secret established. Please run key exchange first.\n");
        return;
    }

    printf("Receiving message...\n");
    unsigned int message_len;
    if (recv(g_socket, (char*)&message_len, sizeof(int), 0) == SOCKET_ERROR){
        handle_error("Failed to receive message length");
    }
    
    // FIX: proper buffer size
    char message[MAX_MESSAGE_LENGTH * 4]; 
    
    if (message_len >= sizeof(message)) {
        printf("Error: Received message size (%u bytes) exceeds buffer capacity.\n", message_len);
        return;
    }

    int received_total = 0;
    while (received_total < (int)message_len) {
        int r = recv(g_socket, message + received_total, message_len - received_total, 0);
        if (r <= 0) {
             handle_error("Failed to receive message body");
        }
        received_total += r;
    }
    message[message_len] = '\0'; // Null-terminate for base64_decode
    
    aes_context context;
    uint8_t key[AES_256_KEY];
    hexStringToBytes(secret, key, &context.key_len);
    setKey(&context, key);
    keySchedule(&context);

    uint8_t hex_text[MAX_MESSAGE_LENGTH * 2];
    
    // FIX: Capture length
    int len = base64_decode(message, hex_text);
    
    decrypt(&context, hex_text, len, hex_text); 
    // Null-terminate the string using the length calculated by decrypt
    hex_text[context.length] = '\0'; 
    printf("Decrypted Message: %s\n", hex_text);
    printf("\n"); 
}


// RSA and KDF helper functions

EVP_PKEY* generate_rsa_key(){
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
    if (!pkey){
        handle_error("Failed to generate RSA key");
    }
    return pkey;
}

void print_rsa_fingerprint(EVP_PKEY* pkey){
    uint8_t *der = NULL;
    int len = i2d_PublicKey(pkey, &der);
    if (len < 0) {
        handle_error("Failed to convert Public key to DER");
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(der, len, hash);
    OPENSSL_free(der);

    printf("RSA Key fingerprint: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++){
        printf("%02x", hash[i]);
        if (i < SHA256_DIGEST_LENGTH -1){
            printf(":");
        }
    }
    printf("\n");
}

void send_rsa_key(SOCKET sock, EVP_PKEY* pkey){
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    char *pem_key;
    long len = BIO_get_mem_data(bio, &pem_key);

    if (send(sock, (char*)&len, sizeof(long), 0) == SOCKET_ERROR){
        handle_error("Failed to send RSA Key length");
    }
    if (send(sock, pem_key, len, 0) == SOCKET_ERROR){
        handle_error("Failed to send RSA key");
    }
    BIO_free(bio);
}

EVP_PKEY* receive_rsa_key(SOCKET sock){
    long len;
    if (recv(sock, (char*)&len, sizeof(long), 0) == SOCKET_ERROR){
        handle_error("Failed to receive RSA key length");
    }
    char *buffer = (char*)malloc(len + 1);
    if (!buffer){
        handle_error("Memory allocation failed");
    }

    int received = 0;
    while (received < len) {
        int ret = recv(sock, buffer + received, len - received, 0);
        if (ret <= 0){
            handle_error("Failed to receive RSA key");
        }
        received += ret;
    }
    buffer[len] = '\0';

    BIO *bio = BIO_new_mem_buf(buffer, len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey){
        handle_error("Failed to parse RSA key");
    }
    BIO_free(bio);
    free(buffer);
    return pkey;
}

uint8_t* sign_data(EVP_PKEY* pkey, const uint8_t* data, int data_len, unsigned int* sig_len){
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx){
        handle_error("EVP_MD_CTX_new failed");
    }
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        handle_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSign(mdctx, NULL, (size_t*)sig_len, data, data_len) != 1) {
        handle_error("EVP_DigestSign (size) failed");
    }

    uint8_t* sig = (uint8_t*)malloc(*sig_len);
    if (!sig) handle_error("Malloc failed");

    if (EVP_DigestSign(mdctx, sig, (size_t*)sig_len, data, data_len) != 1) {
        handle_error("EVP_DigestSign (sign) failed");
    }

    EVP_MD_CTX_free(mdctx);
    return sig;
}

int verify_signature(EVP_PKEY* pkey, const uint8_t* data, int data_len, uint8_t* sig, unsigned int sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_error("EVP_MD_CTX_new failed");

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        handle_error("EVP_DigestVerifyInit failed");
    }

    int ret = EVP_DigestVerify(mdctx, sig, sig_len, data, data_len);
    EVP_MD_CTX_free(mdctx);
    return ret;
}
//create a key locally from password
char* create_key_from_password(){
    printf("Enter password: ");
    char password[MAX_PASSWORD_LENGTH];
    scanf("%s", password);

    uint8_t derived_key[32];
    
    // Calculate required hex buffer size (2 hex chars per byte + null terminator)
    int pwd_len = strlen(password);
    char *password_hex = (char*)malloc(pwd_len * 2 + 1);
    if (!password_hex) handle_error("Memory allocation failed");
    
    for(int i = 0; i < pwd_len; i++) {
        sprintf(password_hex + (i * 2), "%02x", (unsigned char)password[i]);
    }
    password_hex[pwd_len * 2] = '\0';

    derive_key(password_hex, derived_key);
    free(password_hex);

    // Convert derived Key to Hex for return
    char *final_key_hex = (char*)OPENSSL_malloc(65);
    if (!final_key_hex) {
        handle_error("memory allocation failed");
    }
    for (int i = 0; i < 32; i++){
        sprintf(final_key_hex + (i * 2), "%02X", derived_key[i]);
    }
    final_key_hex[64] = '\0';

    return final_key_hex;
}

void derive_key(const char* shared_secret, uint8_t* derived_key) {
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[4], *p = params;
    
    printf("Fetching HKDF...\n");
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        handle_error("EVP_KDF_fetch failed");
    }
    
    printf("Creating KDF Context...\n");
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL) {
        handle_error("EVP_KDF_CTX_new failed");
    }
    
    printf("Setting KDF Parameters...\n");
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void*)shared_secret, strlen(shared_secret));
    *p++ = OSSL_PARAM_construct_octet_string("info", (void*)"KeyExchange", strlen("KeyExchange"));
    *p = OSSL_PARAM_construct_end();
    
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        handle_error("EVP_KDF_CTX_set_params failed");
    }

    printf("Deriving Key...\n");
    if (EVP_KDF_derive(kctx, derived_key, 32, NULL) <= 0) {
        handle_error("HKDF key derivation failed");
    }
    EVP_KDF_CTX_free(kctx);
    
    printf("Derived Session Key (HKDF-SHA256): ");
    for(int i = 0; i < 32; i++) printf("%02x", derived_key[i]);
    printf("\n");
}


