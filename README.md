# P1-Project

AES Encryption & Cryptography Toolkit (C Implementation)

This repository contains the source code for our AES encryption and decryption implementation written in C. It was developed as part of Project 1 (P1) and demonstrates a working symmetric encryption system, including key handling and encoding utilities.

---

## Features

- AES encryption and decryption implementation
- Symmetric key handling and key exchange utilities
- Base64 encoding and decoding
- Test program for validation
- Simple command-line driven main program

---

## Repository Structure
```
/ (root)
├── aes.c # AES implementation
├── aes.h # AES interface definitions
├── base64.c # Base64 encoding/decoding
├── base64.h
├── Keyexchange.c # Key exchange utilities
├── Keyexchange.h
├── Main.c # Main application entry point
├── tests.c # Test cases
├── old_helpers.c # Legacy helper code
├── main_program.exe # Precompiled binary (optional)
├── README.md # Project documentation
```
---

## Requirements

To build and run this project, you will need:

- A C compiler (e.g. `gcc` or `clang`)
- A Unix-like environment (Linux/macOS) or Windows with a compatible shell
- Standard C libraries

---
## Hash sum for main program
```
SHA-3 SUM: 3bb79b04031bbeab93745935575aaea21a94fa2be5da6b063f6547399\\8b496730e409d96814c1cde568dbd1159cfe4e0cbf69b4f2f956a12080f652efd9fed6d
SHA-2 (512) SUM: f6da18dd55e2ddb63b2778c268e2cab055fe5fc1e5b9b58b4103cc974\\ee73aae7d3cad6dad63c3c826c37c7b4a555d43a93f84c777bfa34aee5fea76d5337a8
```
---
## Installation

### 1. Clone the Repository

```sh
git clone https://github.com/magnus-hgk/P1-Project.git
cd P1-Project
```
## 2. Compile the program using gcc
```sh
gcc -std=c11 -Wall -Wextra -O2 \
    -o aes_program Main.c aes.c base64.c Keyexchange.c
```
We had some linker issues when compiling the full program, this helped us.
```sh
GCC_PATH%" Main.c keyexchange.c aes.c base64.c -o MyProgram_Static.exe ^
    -I C:\msys64\ucrt64\include ^
    -L C:\msys64\ucrt64\lib ^
    -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 ^
    -static
```

This will produce an executable named `aes_program`.

## Running the Program
After compiling, run the program with:
`./aes_program`


---
## Contributions
All contributions are welcome!
