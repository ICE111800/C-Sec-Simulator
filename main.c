/* main.c */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "virus_utils.h"

// 模組函式宣告 
extern void run_virus_simulator(); // 病毒模擬器 
extern void run_ransomware_demo(); // 勒索軟體演示 
extern void run_antivirus_scanner(); // 防病毒掃描程序 

int main(void)
{
	int choice;
	srand((unsigned int)time(NULL));
	
	do
	{
		printf("\n =======================================\n");
		printf("\n ----- C 語言資安模擬系統 -----\n");
		printf("\n =======================================\n");
		printf("1. [病毒模組] 病毒潛伏、XOR 破壞、開機自啟動\n");
		printf("2. [勒索模組] TEA 高階加密與贖金機制\n");
		printf("3. [防毒模組] 掃瞄並偵測病毒特徵\n");
		printf("0. 離開系統\n");
		printf(" ---------------------------------------\n");
		printf("請輸入演示選項 : ");
		if (scanf("%d", &choice) != 1)
		{
			while (getchar() != '\n'); // 清除錯誤輸入
			choice = -1;
		}
		while (getchar() != '\n'); // 清除 scanf 留下的換行符 
		
		switch(choice)
		{
			case 1:
				run_virus_simulator();
				break;
			case 2:
				run_ransomware_demo();
				break;
			case 3:
				run_antivirus_scanner();
				break;
			case 0:
				printf("結束程式，感謝使用!\n");
				break;
			default:
				printf("無效的選項，請重新輸入。\n");
		}
	} while(choice != 0);
	



	
	return 0;
} 
