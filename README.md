# Google_Password_Stealer

## Overview
This project is a Pure C application designed to decrypt saved passwords from Google Chrome's 'Login Data' file, utilizing the encrypted key stored in Chrome's 'Local State' file. And also save them to a separate file.

### Objectives
- Extract the encrypted key from the 'Local State' file.
- Decrypt the key using Windows Data Protection API (DPAPI).
- Decrypt passwords from the 'Login Data' file using the decrypted key.

## Implementation
The project uses C and incorporates various libraries alongside Windows-specific APIs.

### Key Features
- Extraction and Base64 decoding of the encrypted key.
- Decryption of the key using DPAPI.
- Decoding and decrypting of saved passwords in Chrome.

## Current Status
🚧 Under development.

## Dependencies and Installation

### Dependencies
1. **cJSON** for JSON parsing - [Download here](https://github.com/DaveGamble/cJSON)
2. **OpenSSL** for AES encryption - Typically included in most C development environments. If not, [download here](https://www.openssl.org/source/)
3. **SQLite** for interacting with Chrome's SQLite databases - [Download here](https://github.com/sqlite/sqlite)

### Installation
Clone the repository:
git clone [repository URL]
cd [repository directory]
