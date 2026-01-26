#ifndef AES_H
#define AES_H

#include <stdint.h>

// -= AES CONSTANTS =-
#define AES_128_KEY 16
#define AES_192_KEY 24
#define AES_256_KEY 32

#define ROWS 4
#define COLUMNS 4
#define BLOCK_SIZE (ROWS * COLUMNS)

// -= AES CONTEXT STRUCT =-
typedef struct 
{   
    int blocks;
    int rounds;
    int length;
    int key_len;

    uint8_t key[AES_256_KEY];
    uint8_t aes_blocks[256][ROWS][COLUMNS];
    uint8_t round_keys[15][ROWS][COLUMNS];
} aes_context;

// -= AES CORE FUNCTIONS =-
void setKey(aes_context *context, const uint8_t *key);
void keySchedule(aes_context *context);

void aesEncryptBlock(aes_context *context, uint8_t block[BLOCK_SIZE], int block_number);
void aesDecryptBlock(aes_context *context, uint8_t block[BLOCK_SIZE], int block_number);

/* -= MESSAGE HELPERS =- */
uint8_t* encrypt(aes_context *context, const char *plain_text, int *out_len);
uint8_t* decrypt(aes_context *context, uint8_t *encrypted_text, int encrypted_len, int *out_len);

// -= HELPER FUNCTIONS AND PRIMITIVES =-
uint8_t galoisMultiplication(uint8_t a, uint8_t b);
void mixColumn(uint8_t col[ROWS], const uint8_t gf[ROWS][COLUMNS]);
void shiftRow(uint8_t state[ROWS][COLUMNS]);
void inverseShiftRow(uint8_t state[ROWS][COLUMNS]);
int padPlainText(uint8_t *data, int len);
int removePadding(uint8_t *data, int len);

#endif
