# C 語言資安與端點防禦模擬系統 (C-Sec-Simulator)

一個基於 C 語言實作的教學/驗證級端點安全（Endpoint Security）模擬系統。整合了基礎病毒行為模擬（原地 XOR、隱藏、註冊表持久化）、TEA 高階分組加密（模擬勒索軟體）、反法證數據覆寫（Data Wiping），以及遞迴防毒掃描與自動修復報告機制。

---

## 系統架構與模組設計
* **`main.c`**：互動式 CLI 主控台選單
* **`virus_utils.h/.c`**：共通資安特徵偵測、檔名判斷與還原工具
* **`virus_simulator.c`**：模擬原地 XOR 感染、檔案隱藏與註冊表持久化
* **`antivirus_scanner.c`**：遞迴檔案掃描、病徵判斷與結構化報表產出
* **`ransomware_demo.c`**：TEA 128-bit 加解密、Anti-Forensics 亂數覆寫與勒索警示


### 核心模組功能表
| 模組 | 檔案 | 核心技術/機制 | 說明 |
| :--- | :--- | :--- | :--- |
| **主控台** | `main.c` | CLI 狀態機、防呆輸入清空 | 提供互動式選單切換模擬情境 |
| **病毒模擬** | `virus_simulator.c` | `fopen("rb+")` 原地 XOR (`0xDC`)、`SetFileAttributes`、`RegSetValueEx` | 模擬勒索前身的混淆破壞、隱身與 Windows 啟動項持久化 |
| **防毒模組** | `antivirus_scanner.c` | 遞迴遍歷、特徵比對 | 掃描 `.txt`/`.locked`，自動還原 XOR 病毒並產出報表 (`report_*.txt`) |
| **勒索模組** | `ransomware_demo.c` | TEA 128-bit 對稱加密、ZeroBytePadding、**Anti-Forensics 亂數覆寫** | 實作檔案加密鎖定、密碼驗證防護（3次鎖定）、改桌布與自動跳出勒索信 |
| **工具箱** | `virus_utils.c/.h` | 簽名檢查、跨平台路徑宏 (`PATH_SEP`) | 提供跨模組的特徵檢查與通用常數定義 |

---

## 實作特點與範圍 (Implementation Highlights)
* **端點行為模擬**：練習 Win32 註冊表寫入（模擬持久化）、檔案屬性修改（隱藏）與基礎 XOR 破壞。
* **簡易資料覆寫**：檔案刪除前以隨機位元 (`rand() % 256`) 覆寫內容（教學概念展示，非對抗進階硬碟鑑識）。
* **區塊加解密**：實作 TEA 演算法（32 輪迭代、黃金比例常數 `0x9e3779b9`）進行對稱加解密。
* **基本防呆與邊界**：操作支援 3 次密碼重試鎖定；掃描器加入路徑過濾以略過自身產出之報告檔。

> **Note**: 本專案為 C 語言系統程式與資安概念練習（Sandbox / PoC），機制皆經簡化。

---

## 快速開始 (Quick Start)

### 環境需求
* Windows 系統（因依賴 `windows.h`、`ShellExecute`、`SystemParametersInfo` 進行桌布/視窗互動與註冊表操作）
* GCC / Clang 或 MSVC 編譯器

### 編譯與執行
```bash
# 範例編譯指令 (以 GCC 為例)
gcc main.c virus_simulator.c antivirus_scanner.c ransomware_demo.c virus_utils.c -o sec_sim.exe

# 執行系統
sec_sim.exe
