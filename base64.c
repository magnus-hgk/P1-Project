#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "base64.h"

/*

    Based on work by https://github.com/elzoughby/Base64/tree/master

*/

// Base64 character set - Contains only printable characters
static const char BASE64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const uint8_t *input, int input_length, char *output)
{
    int input_index = 0;
    int output_index = 0;

    // Process input in 3-byte blocks - Base64 increase lenght by ~33%
    while (input_index < input_length) {
        uint8_t input_block[3] = {0, 0, 0};
        uint8_t encoded_block[4];
        int bytes_read = 0;

        // Read 3 bytes - Unless at end of input
        for (bytes_read = 0; bytes_read < 3 && input_index < input_length; bytes_read++) {
            input_block[bytes_read] = input[input_index++];
        }

        // Convert 3 bytes into 4 Base64 values
        encoded_block[0] = (input_block[0] >> 2) & 0x3F;
        encoded_block[1] = ((input_block[0] & 0x03) << 4) |
                           ((input_block[1] >> 4) & 0x0F);
        encoded_block[2] = ((input_block[1] & 0x0F) << 2) |
                           ((input_block[2] >> 6) & 0x03);
        encoded_block[3] = input_block[2] & 0x3F;

        // Write encoded output or padding based on the base64 characterset.
        for (int i = 0; i < 4; i++) {
            if (i <= bytes_read) {
                output[output_index++] = BASE64_ALPHABET[encoded_block[i]];
            } else {
                output[output_index++] = '=';
            }
        }
    }

    // Null-terminate output 
    output[output_index] = '\0';

    // Returns the lenght of the output
    return output_index;
}

int base64_decode(const char *input, uint8_t *output)
{
    int input_length = strlen(input);
    int input_index = 0;
    int output_index = 0;

    // Process input in 4-character blocks - Base64 decode reduces size by ~25%
    while (input_index < input_length) {
        uint8_t decoded_block[3];
        uint8_t encoded_block[4] = {0, 0, 0, 0};
        int padding_count = 0;

        // Decode Base64 characters
        for (int i = 0; i < 4 && input_index < input_length; i++) {
            if (input[input_index] == '=') {
                encoded_block[i] = 0;
                padding_count++;
                input_index++;
            } else {
                const char *position = strchr(BASE64_ALPHABET, input[input_index++]);
                encoded_block[i] = position ? (uint8_t)(position - BASE64_ALPHABET) : 0;
            }
        }

        // Convert Base64 values back to bytes
        decoded_block[0] = (encoded_block[0] << 2) |
                           ((encoded_block[1] >> 4) & 0x03);
        decoded_block[1] = ((encoded_block[1] & 0x0F) << 4) |
                           ((encoded_block[2] >> 2) & 0x0F);
        decoded_block[2] = ((encoded_block[2] & 0x03) << 6) |
                           encoded_block[3];

        // Map decoded bytes to output.
        for (int i = 0; i < 3 - padding_count; i++) {
            output[output_index++] = decoded_block[i];
        }
    }

    // Returns the length of the output.
    return output_index;
}
