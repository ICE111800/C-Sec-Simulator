// virus_utils.c - 提供病毒相關工具函式
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "virus_utils.h"

// 偵測是否被 XOR 病毒感染 (檢查檔案末尾有無簽名)
int is_infected(const char *filename)
{
    FILE *fp = fopen(filename, "rb"); // 改用 rb 讀取，避免二進位檔案讀取問題 
    if (!fp) return 0;
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size < (long)strlen(VIRUS_SIGNATURE))
    {
    	fclose(fp);
    	return 0;
	}
    
    long read_size = (size > 256) ? 256 : size;
    fseek(fp, -read_size, SEEK_END);
    char *buf = malloc(read_size + 1);
    size_t len = fread(buf, 1, read_size, fp);
    buf[len] = '\0';
    fclose(fp);
    
    int infected = (strstr(buf, VIRUS_SIGNATURE) != NULL);
    free(buf);
    return infected;
}

// 偵測是否為勒索加密檔 (純粹靠副檔名，因為內容已不可讀)
int is_locked_by_ransom(const char *filename)
{
	const char *ext = strrchr(filename, '.');
	return (ext && strcmp(ext, RANSOM_EXTENSION) == 0);
}

void clean_virus_signature(const char *filename)
{
	// 強制解除隱藏與唯讀屬性，否則無法寫入 
	SetFileAttributes(filename, FILE_ATTRIBUTE_NORMAL);
	
	// 再次執行一次 XOR 0xDC 即可還原內容
    // 因為 XOR 特性 (A ^ B) ^ B = A
    FILE *fp =fopen(filename, "rb");
    if (!fp) return;
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);
    
    unsigned char *buffer = malloc(size + 1); // 多給一個空間放 \0
    if (!buffer)
    {
    	fclose(fp);
    	return;
	}
    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);
    
    // 尋找簽名位置並截斷 (假設簽名在最後)
    // 尋找 "//INFECTED" 字串 
    unsigned char *sig_ptr = (unsigned char *)strstr((char *)buffer, VIRUS_SIGNATURE);
    
    if (sig_ptr)
    {
    	long data_size = (sig_ptr - buffer); // 算出簽名之前的資料長度 排除簽名之前的 \n 
    	
    	// 往前修剪換行符號 (\n 或 \r) 
    	while (data_size > 0 && (buffer[data_size - 1] == '\n' || buffer[data_size - 1] == '\r'))
    	{
    		data_size--;
		}
    
	    // 只對真正的資料內容進行反 XOR 
	    for (long i = 0; i < data_size; i++)
	    {
	    	buffer[i] ^= 0xDC;
		}
		
		// 寫回檔案 (wb 模式會覆蓋原檔)
		fp = fopen(filename, "wb");
		if (fp)
		{
			fwrite(buffer, 1, data_size, fp); // 只寫回解密後的資料，不寫簽名 
			fclose(fp);
			// 再次確認屬性為正常 
			SetFileAttributes(filename, FILE_ATTRIBUTE_NORMAL);
		}
	}
	free(buffer);
}













