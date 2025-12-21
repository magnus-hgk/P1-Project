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

---

## Requirements

To build and run this project, you will need:

- A C compiler (e.g. `gcc` or `clang`)
- A Unix-like environment (Linux/macOS) or Windows with a compatible shell
- Standard C libraries

---

## Installation

### 1. Clone the Repository

```sh
git clone https://github.com/magnus-hgk/P1-Project.git
cd P1-Project
```
## 2. Compile the program using gcc

gcc -std=c11 -Wall -Wextra -O2 \
    -o aes_program Main.c aes.c base64.c Keyexchange.c

This will produce an executable named `aes_program`.

## Running the Program
After compiling, run the program with:
`./aes_program`



## Contributions
All contributions are welcome!
