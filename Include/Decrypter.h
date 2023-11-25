#ifndef _DECRYPTER_
#define _DECRYPTER_
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <wincrypt.h>
BYTE* DecryptPassword(DATA_BLOB CipherData, DATA_BLOB SecretKey);


#endif