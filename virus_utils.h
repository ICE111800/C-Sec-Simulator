// virus_utils.h

#ifndef VIRUS_UTILS_H
#define VIRUS_UTILS_H

#define PATH_MAX_LEN 1024

// 定義病毒簽名  
#define VIRUS_SIGNATURE "//INFECTED" 
// 定義勒索簽名  
#define RANSOM_EXTENSION ".locked"
//#define RANSOM_NOTE "//ENCRYPTED"

// 目標資料夾  
//#define TARGET_FOLDER "F:\\C\\learn\\My_project\\testdata"
#define TARGET_FOLDER "testdata"

// Window or Linux 跨平台 路徑分隔號 
#ifdef _WIN32
#define PATH_SEP "\\"
#else
#define PATH_SEP "/"
#endif 

//  宣告函式，不要在這裡定義（定義只留在一個 .c 檔案）
int is_infected(const char *filename);
int is_locked_by_ransom(const char *filename);

void clean_virus_signature(const char *filename);

void run_virus_simulator(); // 提供 main.c 呼叫 
void run_ransomware_demo();
void run_antivirus_scanner();

#include <windows.h>


#endif
