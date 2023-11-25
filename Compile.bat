@echo off
gcc -o Testing/main Testing/main.c Src/GetDbData.c Src/cJSON.c Src/GetSecretKey.c Src/Decrypter.c -lssl -lcrypto -lcrypt32  -lsqlite3
echo Done...
pause>nul