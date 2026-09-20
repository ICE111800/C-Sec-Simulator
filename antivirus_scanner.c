// antivirus_scanner.c 防毒模組
#include <stdio.h> //標準輸入輸出函式庫，用於檔案讀寫與螢幕顯示 
#include <stdlib.h> // 標準工具函式庫，用於動態記憶體與系統工具 
#include <string.h> // 字串處理函式庫，用於比較與串接路徑 
#include <dirent.h> // 目錄操作函式庫，用於開啟與讀取資料夾內容 
#include <sys/stat.h> // 檔案狀態函式庫，用於判斷是檔案還是資料夾 
#include <time.h> // 時間函式庫，用於產生日誌時間戳記 
#include "virus_utils.h"

#define PATH_MAX_LEN 1024

// 統計變數
static int g_index = 0; 		// 目前掃描的檔案 index 計數器 
static int g_total = 0;			// 總掃描檔案數量統計 
static int g_total_cleaned = 0;	// 成功修復的檔案總數統計 
static int g_virus_count = 0;	// 偵測到的 XOR 病毒檔案數量 
static int g_ransom_count = 0;	// 偵測到的 TEA 勒索檔案數量 

// 從完整路徑中提取純檔案名稱 
const char* get_filename(const char *path) {
    const char *slash1 = strrchr(path, '\\'); // 找尋 Windows 格式的反斜線 
    const char *slash2 = strrchr(path, '/'); // 找尋 Linux/Unix 風格的斜線 
    const char *slash = (slash1 > slash2) ? slash1 : slash2; // 取最後一個斜線位置  
    return (slash) ? slash + 1 : path; // 返回斜線後的第一個字元位址  
}

// 格式化時間戳 (檔名用)
static void format_timestamp(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    struct tm *tmv_ptr = localtime(&t);
    if (tmv_ptr) tmv = *tmv_ptr;
#else
    localtime_r(&t, &tmv);
#endif
    strftime(buf, n, "%Y%m%d_%H%M%S", &tmv);
}

// 格式化人類閱讀時間 (報告用)
static void human_readable_time(char *buf, size_t n, time_t t) {
    struct tm tmv;
#ifdef _WIN32
    struct tm *tmv_ptr = localtime(&t);
    if (tmv_ptr) tmv = *tmv_ptr;
#else
    localtime_r(&t, &tmv);
#endif
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tmv);
}

// 遞迴掃描函數
void scan_directory_recursive(const char *folder, FILE *report) {
    DIR *dir = opendir(folder); // 試圖打開指定的資料夾  
    if (!dir) {	// 如果開啟失敗
        fprintf(report, "Error: 無法開啟資料夾 %s\n", folder);
        return; // 結束此層遞迴  
    }

    struct dirent *entry; // 定義目錄項指標，代表讀到的檔案或子資料夾  
    struct stat st;		 // 定義檔案狀態結構，用於存放檔案細節資訊 
    char path[PATH_MAX_LEN]; // 定義緩衝區，儲存串接後的完整路徑  

    while ((entry = readdir(dir)) != NULL) { // 迴圈讀取資料夾內的每一個項目  
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) // 忽略 "."(目前目錄) 與 ".."(上層目錄)，防止死迴圈遞迴 
            continue;
        if (entry->d_name[0] == '.') 
            continue;
		
		// 串接完整的檔案路徑 (父資料夾 + 分隔符號 + 檔案名) 
        snprintf(path, sizeof(path), "%s%s%s", folder, PATH_SEP, entry->d_name);

		// 獲取檔案狀態（如大小、屬性、類型）
        if (stat(path, &st) != 0)
            continue; // 失敗跳過

		// 如果這是一個資料夾 
        if (S_ISDIR(st.st_mode)) { 
            scan_directory_recursive(path, report); // 向下執行遞迴掃描子資料夾 
            continue; // 處理完子資料夾後繼續下一個項目 
        }

        // 避免掃描報告檔  
        if (strstr(entry->d_name, "report_") == entry->d_name)
            continue;

        // 只掃描 .txt 和 .locked
        if (!(strstr(entry->d_name, ".txt") || strstr(entry->d_name, ".locked")))
            continue;

        g_total++;
        g_index++;

        int virus_found = is_infected(path);  // 呼叫函式檢查是否有 XOR 病毒簽名 
        int ransom_found = is_locked_by_ransom(path); // 呼叫函式檢查是否為 TEA 勒索檔 
        int cleaned = 0;
        char remarks[128] = "無異常";

        if (virus_found) { // 當發現 XOR 病毒  
            clean_virus_signature(path);  // 呼叫函式執行數據還原與移除簽名 
            if (!is_infected(path)) {    // 二次檢查確保簽名已消失 
                cleaned = 1;			// 標記為修復成功  
                g_virus_count++;	    // XOR 病毒 + 1 
                g_total_cleaned++;      // 總修復計數 + 1
                strcpy(remarks, "已自動修復 XOR 損壞");
            } else {
                strcpy(remarks, "修復失敗，請檢查權限");
            }
        } else if (ransom_found) { 		// 若發現 TEA 勒索加密 
            g_ransom_count++; 			// 勒索計數 + 1
            strcpy(remarks, "威脅：需金鑰解密 (.locked)");
        }

        fprintf(report, "%-4d %-45s %-10s %-10s %-12s %-25s\n",
                g_index, get_filename(path),
                virus_found ? "YES" : "NO",
                ransom_found ? "YES" : "NO",
                cleaned ? "YES" : "NO",
                remarks);
    }
    closedir(dir);
}

// 主掃描控制函式
void run_antivirus_scanner() {
    g_index = 0;
    g_total = 0;
    g_total_cleaned = 0;
    g_virus_count = 0;
    g_ransom_count = 0;
    
    char ts[32]; // 定義時間戳記緩衝區 
    format_timestamp(ts, sizeof(ts)); // 產生成報告用的時間字串 

    char report_path[512]; // 定義報告儲存路徑緩衝區 
    snprintf(report_path, sizeof(report_path), "%s%sreport_%s.txt", TARGET_FOLDER, PATH_SEP, ts);

    FILE *report = fopen(report_path, "w"); // 以寫入模式建立報告檔案 
    if (!report) {
        perror("無法建立報告檔");
        return;
    }
    
    clock_t start_clock = clock();
    time_t t_start = time(NULL);
    char start_human[64];
    human_readable_time(start_human, sizeof(start_human), t_start);

    fprintf(report, "============================================================================================================\n");
    fprintf(report, "===                             C 語言資安模擬系統 - 防毒報告                              ===\n");
    fprintf(report, "============================================================================================================\n");
    fprintf(report, "開始時間 : %s\n", start_human);
    fprintf(report, "掃描目標 : %s\n\n", TARGET_FOLDER);
    fprintf(report, "%-4s %-45s %-10s %-10s %-12s %-25s\n",
            "No.", "檔案名稱", "病毒簽名", "勒索威脅", "是否修復", "掃描備註");
    fprintf(report, "------------------------------------------------------------------------------------------------------------\n");

    scan_directory_recursive(TARGET_FOLDER, report); // 啟動遞迴掃描 

    clock_t end_clock = clock();
    time_t t_end = time(NULL);
    char end_human[64];
    human_readable_time(end_human, sizeof(end_human), t_end);
    double elapsed_sec = (double)(end_clock - start_clock) / CLOCKS_PER_SEC;

    fprintf(report, "------------------------------------------------------------------------------------------------------------\n");
    fprintf(report, "結束時間 :  %s\n", end_human);
    fprintf(report, "掃描耗時 :  %.3f 秒\n", elapsed_sec);
    fprintf(report, "總掃描檔案數量         :  %d\n", g_total);
    fprintf(report, "發現 XOR 感染檔案      :  %d\n", g_virus_count);
    fprintf(report, "發現 TEA 加密威脅      :  %d\n", g_ransom_count);
    fprintf(report, "順利還原檔案數量       :  %d\n", g_total_cleaned);
    fprintf(report, "------------------------------------------------------------------------------------------------------------\n");
    fprintf(report, "\n[安全建議]：\n1. 針對被標記為「勒索威脅」的檔案，請使用主選單選取 [2. 勒索模組] 並輸入正確金鑰進行解密。\n2. XOR 病毒已由掃描器嘗試原地還原。\n");

    fclose(report);
    printf("\n[掃描完成] 偵測到 %d 個威脅，已產生詳細報告: %s\n", g_virus_count + g_ransom_count, report_path);
}
