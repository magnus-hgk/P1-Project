#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "base64.h"
#include "aes.h"
#include <stdint.h>

#define ASSERT_EQ_BUF(a, b, len) \
    assert(memcmp((a), (b), (len)) == 0)

#define ASSERT_EQ_INT(a, b) \
    assert((a) == (b))

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


void testGaloisMultiplication(void)
{
    assert(galoisMultiplication(0x57, 0x13) == 0xFE);
    assert(galoisMultiplication(0x02, 0x03) == 0x06);
    assert(galoisMultiplication(0xFF, 0x01) == 0xFF);

    printf("- galoisMultiplication      OK\n");
}

void testMixColumn(void)
{
    uint8_t col[4] = {0xdb, 0x13, 0x53, 0x45};
    uint8_t original[4];
    memcpy(original, col, 4);

    mixColumn(col, rijndael_galois_field);
    mixColumn(col, inverse_rijndael_galois_field);

    ASSERT_EQ_BUF(col, original, 4);
    printf("- mixColumn                 OK\n");
}

void testShiftRows(void)
{
    uint8_t state[ROWS][COLUMNS] = {
        {0x00,0x01,0x02,0x03},
        {0x10,0x11,0x12,0x13},
        {0x20,0x21,0x22,0x23},
        {0x30,0x31,0x32,0x33}
    };

    uint8_t original[ROWS][COLUMNS];
    memcpy(original, state, sizeof(state));

    shiftRow(state);
    inverseShiftRow(state);

    ASSERT_EQ_BUF(state, original, sizeof(state));
    printf("- shiftRows                 OK\n");
}

void testPadding(void)
{
    uint8_t buffer[32] = "Troels";
    int len = 6;

    int padded = padPlainText(buffer, len);
    ASSERT_EQ_INT(padded % 16, 0);

    int unpadded = removePadding(buffer, padded);
    ASSERT_EQ_INT(unpadded, len);

    printf("- Padding                   OK\n");
}

void testAES128EncryptDecrypt(void)
{
    aes_context context;
    uint8_t key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F
    };

    uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,
        0xCC,0xDD,0xEE,0xFF
    };

    uint8_t expected_cipher[16] = {
        0x69,0xC4,0xE0,0xD8,
        0x6A,0x7B,0x04,0x30,
        0xD8,0xCD,0xB7,0x80,
        0x70,0xB4,0xC5,0x5A
    };

    uint8_t buffer[16];

    context.key_len = AES_128_KEY;
    setKey(&context, key);
    keySchedule(&context);

    memcpy(buffer, plaintext, 16);
    aesEncryptBlock(&context, buffer, 1);

    ASSERT_EQ_BUF(buffer, expected_cipher, 16);

    aesDecryptBlock(&context, buffer, 1);
    ASSERT_EQ_BUF(buffer, plaintext, 16);

    printf("- AES-128 encrypt/decrypt   OK\n");
}

int main(void)
{
    
    printf("\n-= Testing all parameters! =-\n\n");

    testShiftRows();
    testMixColumn();
    testGaloisMultiplication();
    testPadding();
    testAES128EncryptDecrypt();
    
    printf("\n-= All tests passed! =-\n");

    return EXIT_SUCCESS;
}
