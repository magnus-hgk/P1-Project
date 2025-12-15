#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base64.h"
#include <stdint.h>


// ROUNDS
#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14

// KEYS
#define INITIAL_KEY 1
#define AES_128_KEY 16
#define AES_192_KEY 24
#define AES_256_KEY 32

#define KEY_SIZE 16
#define MAX_WORDS_256 60

// BITS AND  BYTES
#define BITS_PER_BYTE 8

// CONTEXT, STATE, WORD
#define ROWS 4
#define COLUMNS 4
#define WORD 4
#define STATE_SIZE 16

// MESSAGE SIZES
#define MAX_NUMBER_OF_BLOCKS 256
#define BLOCK_SIZE ROWS * COLUMNS
#define MAX_MESSAGE_LENGTH MAX_NUMBER_OF_BLOCKS * BLOCK_SIZE

// TYPEDEF AES CONTEXT
typedef struct 
{   
    int blocks;
    int rounds;
    int length;
    int key_len;

    uint8_t key[AES_256_KEY];
    uint8_t aes_blocks[MAX_NUMBER_OF_BLOCKS][ROWS][COLUMNS];
    uint8_t round_keys[AES_256_ROUNDS + INITIAL_KEY][ROWS][COLUMNS];
} aes_context;


// The AES Substitution Box (S-Box)
static const uint8_t sbox[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   // F
};

// The AES Inverse Substitution Box (InvS-Box)
static const uint8_t rsbox[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  // F
};

static const uint8_t rijndael_galois_field[ROWS][COLUMNS] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

static const uint8_t inverse_rijndael_galois_field[ROWS][COLUMNS] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
};


int stringToHex(const char string[], uint8_t hex[])
{
    int i = 0;
    
    while (string[i] != '\0')
    {
        hex[i] = (uint8_t)string[i];  // store numeric (hex) value
        i++;
    }

    return i;
}

int padPlainText(uint8_t *data, int data_len)
{
    int pad_len = STATE_SIZE - (data_len % STATE_SIZE); // Calculates amount of bytes to add

    for (int i = 0; i < pad_len; i++)
    {
        data[data_len + i] = pad_len;
    }

    return data_len + pad_len;
}

int removePadding(uint8_t *data, int data_len)
{
    int pad_len = data[data_len - 1];
    if (pad_len < 1 || pad_len > STATE_SIZE)
    {
        return data_len;
    }
    return data_len - pad_len;
}


void printHex(uint8_t hex[], int len)
{
    for (int i = 0; i < len ; i++)
    {
        printf("%02X ", hex[i]);
    }
    printf("\n");
}

void substituteState(uint8_t state[ROWS][COLUMNS], const uint8_t sbox[256])
{
    for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                state[row][column] = sbox[state[row][column]];
            }
        }
}

void substituteBlocks(aes_context *context, const uint8_t sbox[256])
{
    for (int i = 0; i < context->blocks; i++)
    {
        substituteState(context->aes_blocks[i], sbox);
    }
}


void hexToBlock(const uint8_t hex[MAX_MESSAGE_LENGTH], aes_context *context)
{
    int counter = 0;
    for (int block = 0; block < context->blocks; block++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                context->aes_blocks[block][row][column] = hex[counter++];
            }
        }
    }
    
}

void blockToHex(uint8_t hex[MAX_MESSAGE_LENGTH], const aes_context *context)
{
    int counter = 0;
    for (int block = 0; block < context->blocks; block++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            for (int row = 0; row < ROWS; row++)
            {
                hex[counter++] = context->aes_blocks[block][row][column];
            }
        }
    }
}


uint8_t galoisMultiplication(uint8_t multiplicand, uint8_t multiplier)
{
    uint8_t product = 0;

    for (int i = 0; i < BITS_PER_BYTE; i++)
    {
        if (multiplier & 1)
        {
            product = product ^ multiplicand;
        }

        uint8_t overflow = multiplicand & 0x80;

        multiplicand = multiplicand << 1;

        if (overflow != 0)
        {
            multiplicand = multiplicand ^ 0x1B;
        }

        multiplier = multiplier >> 1;
    }

    return product;
}


void mixColumn(uint8_t word[ROWS], const uint8_t galois_field[ROWS][COLUMNS])
{
    uint8_t result[WORD];

    for (int i = 0; i < ROWS; i++)
    {
        result[i] =
        galoisMultiplication(word[0], galois_field[i][0]) ^
        galoisMultiplication(word[1], galois_field[i][1]) ^
        galoisMultiplication(word[2], galois_field[i][2]) ^
        galoisMultiplication(word[3], galois_field[i][3]);
    }

    for (int i = 0; i < ROWS; i++)
    {
        word[i] = result[i];
    }
}


void mixColumns(uint8_t state[ROWS][COLUMNS], const uint8_t gf[ROWS][COLUMNS])
{

    uint8_t state_column[ROWS];
    for (int column = 0; column < COLUMNS; column++)
    {
        for (int row = 0; row < ROWS; row++)
        {
            state_column[row] = state[row][column];
        }
        
        mixColumn(state_column, gf);

        for (int row = 0; row < ROWS; row++)
        {
            state[row][column] = state_column[row];
        }
    }
}

void mixColumnBlocks(aes_context *context)
{
    for (int block = 0; block < context->blocks; block++)
    {        
        mixColumns(context->aes_blocks[block], rijndael_galois_field);       
    }
}


void inverseMixColumnBlocks(aes_context *context)
{
    for (int block = 0; block < context->blocks; block++)
    {        
        mixColumns(context->aes_blocks[block], inverse_rijndael_galois_field);       
    }
}

void shift(uint8_t state[ROWS][COLUMNS], int row)
{

    uint8_t tmp;

    for (int i = 0; i < row; i++)
    {
        tmp           = state[row][0];
        state[row][0] = state[row][1];
        state[row][1] = state[row][2];
        state[row][2] = state[row][3];
        state[row][3] = tmp;
    }
}

void inverseShift(uint8_t state[ROWS][COLUMNS], int row)
{

    uint8_t tmp;

    for (int i = 0; i < row; i++)
    {
        tmp           = state[row][3];
        state[row][3] = state[row][2];
        state[row][2] = state[row][1];
        state[row][1] = state[row][0];
        state[row][0] = tmp;
    }
}


void shiftRow(uint8_t state[ROWS][COLUMNS])
{   
    for (int i = 1; i < 4; i++)
    {
        shift(state, i);
    } 
}

void inverseShiftRow(uint8_t state[ROWS][COLUMNS])
{   
    for (int i = 1; i < 4; i++)
    {
        inverseShift(state, i);
    }
}


void shiftRows(aes_context *context)
{
    for (int i = 0; i < context->blocks; i++)
    {
        shiftRow(context->aes_blocks[i]);
    }
}

void inverseShiftRows(aes_context *context)
{
    for (int i = 0; i < context->blocks; i++)
    {
        inverseShiftRow(context->aes_blocks[i]);
    }
}

void rotateWord(uint8_t *word)
{
    uint8_t tmp;

    tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

void subWord(uint8_t *word)
{
    for (int i = 0; i < WORD; i++)
    {
        word[i] = sbox[word[i]];
    }
}

void keySchedule(aes_context *context)
{
    int Nr = context->rounds;           // Number of rounds
    int Nk = context->key_len / 4;      // Number of 32-bit words in the key (4, 6, 8)
    int Nb = WORD;                      // Number of columns in a state
    int total_words = Nb * (Nr + 1);    // Total 32-bit words needed for round keys
    uint8_t tmp[WORD];                  // Temporary word for manipulation
    uint8_t words[MAX_WORDS_256][WORD]; // MAXIMUM OF 60 WORDS IN AES-256

    

    for (int i = 0; i < Nk; i++)
    {
        for (int j = 0; j < WORD; j++)
        {
            words[i][j] = context->key[i * 4 + j];
        }
    }

    for (int i = Nk; i < total_words; i++)
    {
        for (int j = 0; j < WORD; j++)
        {
            tmp[j] = words[i - 1][j];
        }

        if (i % Nk == 0)
        {
            rotateWord(tmp);
            subWord(tmp);
            tmp[0] ^= rcon[i - 1];
        } else if (Nk == 8 && i % Nk == 4){

            subWord(tmp);
        }
        


        for (int j = 0; j < WORD; j++)
        {
            words[i][j] = words[i - Nk][j] ^ tmp[j];
        }
        
    }

    for (int round = 0; round <= Nr; round++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            int word_index = round * Nb + column;
            for (int row = 0; row < ROWS; row++)
            {
                context->round_keys[round][row][column] = words[word_index][row];
            }
        }
    }

}



void addKeyToState(uint8_t state[ROWS][COLUMNS], const uint8_t round_key[ROWS][COLUMNS])
{
    for (int row = 0; row < ROWS; row++)
    {
        for (int column = 0; column < COLUMNS; column++)
        {
            state[row][column] ^= round_key[row][column];
        }   
    }
}

void addKeyToBlocks(aes_context *context, int round)
{
    for (int i = 0; i < context->blocks; i++)
    {
        addKeyToState(context->aes_blocks[i], context->round_keys[round]);
    }
}


void setKey(aes_context *context, const uint8_t key[])
{ 
    if (context->key_len != AES_128_KEY && context->key_len != AES_192_KEY && context->key_len != AES_256_KEY)
    {
        printf("Invalid key length!\nExiting!\n");
        exit(EXIT_FAILURE);
    }

    memcpy(context->key, key, context->key_len);

    switch (context->key_len)
    {
    case AES_128_KEY:
        context->rounds = AES_128_ROUNDS;
        break;
    case AES_192_KEY:
        context->rounds = AES_192_ROUNDS;
        break;
    case AES_256_KEY:
        context->rounds = AES_256_ROUNDS;
        break;
    
    default:
        printf("Invalid key length!\nExiting!\n");
        exit(EXIT_FAILURE);
        break;
    }
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
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}


void printBlocksColumn(aes_context *context)
{
    for (int i = 0; i < context->blocks; i++)
    {
        printf("Block %d:\n", i);
        for (int column = 0; column < COLUMNS; column++) 
        {
            for (int row = 0; row < ROWS; row++) 
            {
                printf("%02X ", context->aes_blocks[i][row][column]);
            }
            printf("\n");
        }
        printf("\n");
    }
}


void printBlocksRow(aes_context *context)
{
    for (int i = 0; i < context->blocks; i++)
    {
        printf("Block %d:\n", i);
        for (int row = 0; row < ROWS; row++) 
        {
            for (int column = 0; column < COLUMNS; column++) 
            {
                printf("%02X ", context->aes_blocks[i][row][column]);
            }
            printf("\n");
        }
        printf("\n");
    }
}


void encrypt(aes_context *context, char *plain_text, uint8_t *hex_text)
{

    int plain_text_len = stringToHex(plain_text, hex_text);
    context->length = padPlainText(hex_text, plain_text_len);
    context->blocks = context->length / 16;
    
    hexToBlock(hex_text, context);
    
    int i = 0;
    addKeyToBlocks(context, i);

    for (i = 1; i < context->rounds; i++)
    {
        substituteBlocks(context, sbox);
        shiftRows(context);
        mixColumnBlocks(context);
        addKeyToBlocks(context, i);
    }

    substituteBlocks(context, sbox);
    shiftRows(context);
    addKeyToBlocks(context, i);
    
    blockToHex(hex_text, context);

    printf("Encrypted (hex): ");
    printHex(hex_text, context->length);
}

void decrypt(aes_context *context, char *encrypted_text, uint8_t *hex_text)
{
    context->length = stringToHex(encrypted_text, hex_text); 
    context->blocks = context->length / 16;

    hexToBlock(hex_text, context);

    addKeyToBlocks(context, context->rounds);

    for (int i = context->rounds - 1; i >= 1; i--)
    {
        inverseShiftRows(context);
        substituteBlocks(context, rsbox);
        addKeyToBlocks(context, i);
        inverseMixColumnBlocks(context);
    }

    inverseShiftRows(context);
    substituteBlocks(context, rsbox);
    addKeyToBlocks(context, 0);

    blockToHex(hex_text, context); 

    int original_len = removePadding(hex_text, context->length);
    printf("Plain: ");
    for (int i = 0; i < original_len; i++) 
    {
        printf("%c", hex_text[i]);
    }
    printf("\n");
}


int main(void)
{
    char input_text[MAX_MESSAGE_LENGTH];
    char encrypted_text[MAX_MESSAGE_LENGTH];
    char base64_text[MAX_MESSAGE_LENGTH * 4];

    uint8_t hex_text[MAX_MESSAGE_LENGTH * 2];

    char input_key[AES_256_KEY * 2 + 1];
    uint8_t key[AES_256_KEY];

    aes_context context;   

    // Key Handling
    printf("Input key (hex): ");
    scanf("\n %[^\n]s", input_key);

    hexStringToBytes(input_key, key, &context.key_len);
    setKey(&context, key);
    keySchedule(&context);
    // EO Key handling

    // Choose an action to perform
    int choice = 0;
    int valid = 0;

    while (1)
    {
        do {
            printf("\n---= Choose action =---\n[1] Encrypt\n[2] Decrypt\n[3] Exit\n");
            valid = scanf("%d", &choice);
        } while (valid != 1 && (choice != 1 || choice != 2 || choice != 3));

        switch (choice)
        {
        case 1:
            printf("Input plain text: ");
            scanf("\n %[^\n]s", input_text);

            encrypt(&context, input_text, hex_text);
            int b64_len = base64_encode(hex_text, context.length, base64_text);
            printf("Encrypted (Base64): %s\n", base64_text);
            break;
        
        case 2:
            
            printf("Input encrypted text (base64): ");
            scanf("\n %[^\n]s", input_text);
            
            int hex_len = base64_decode(input_text, hex_text);
            decrypt(&context, (char *)hex_text, hex_text);
            break;
            
        case 3:
            printf("Exiting program!\n");
            exit(EXIT_SUCCESS);

        default:
            printf("Choice invalid!\nExiting program!\n");
            exit(EXIT_FAILURE);
            break;
        }
    }
    

    return EXIT_SUCCESS;

}
