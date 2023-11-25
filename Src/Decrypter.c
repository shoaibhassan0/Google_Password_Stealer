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

#include "../Include/Decrypter.h"

BYTE * Decrypt_AES(const unsigned char *secret_key, const unsigned char *initialization_vector, const unsigned char *encrypted_password, size_t encrypted_length);
BYTE* DecryptPassword(DATA_BLOB CipherData, DATA_BLOB SecretKey) {
	
	int start_index = 3;
	int end_index = 15;
	// Calculate the length of the substring to extract
	int substring_length = end_index - start_index;
	// Allocate memory for the substring
	BYTE *initialisation_vector = malloc(substring_length + 1 * sizeof(BYTE)); // +1 for the null terminator

	memcpy(initialisation_vector, CipherData.pbData + start_index, substring_length);

	// Calculate the length of the key
	size_t len = CipherData.cbData;
	size_t enc_len = 0;
	BYTE *encrypted_password = NULL,*pass = NULL;
	
    if (len >= 32) {  // Assuming 16 characters before and 16 characters after the slice
        // Extract the substring
        enc_len = (len - 15) - 16;
        const BYTE* substring = (BYTE*)CipherData.pbData + 15;

        // Allocate memory for the encrypted password
        encrypted_password = malloc(enc_len);
        memcpy(encrypted_password, substring, enc_len);
		pass = Decrypt_AES(SecretKey.pbData,initialisation_vector,encrypted_password,enc_len);
    }

    // Clean up allocated memory
    free(initialisation_vector);
    free(encrypted_password);

    return pass;  // Modify the return type as needed
}
BYTE * Decrypt_AES(const unsigned char *secret_key, const unsigned char *initialization_vector, const unsigned char *encrypted_password, size_t encrypted_length) {
    EVP_CIPHER_CTX *ctx;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();

    // Initialize the decryption operation with AES-GCM
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, secret_key, initialization_vector);

    // Provide any AAD (Additional Authenticated Data)
    // For GCM mode, this step is optional, set to NULL if not used

    // Decrypt the data
    int len;
    BYTE *decrypted_password = malloc(256 * sizeof(BYTE));  // Adjust the size as needed
    EVP_DecryptUpdate(ctx, decrypted_password, &len, encrypted_password, encrypted_length);

    // Finalize the decryption
    int final_len;
    EVP_DecryptFinal_ex(ctx, decrypted_password + len, &final_len);

    // Assuming the decrypted data is a string
    decrypted_password[len + final_len] = '\0';

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return decrypted_password;
}