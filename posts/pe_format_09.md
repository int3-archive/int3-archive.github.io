---
date: 2025-01-09
title: PE Format บทที่ 9 - การจัดการ Imports (Import Address Table - IAT)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: โปรแกรมส่วนใหญ่บน Windows ไม่ได้ทำงานได้ด้วยตัวเองทั้งหมด แต่ต้องพึ่งพาฟังก์ชันและบริการต่างๆ ที่ระบบปฏิบัติการ (ผ่านทาง Kernel32.dll, User32.dll, Gdi32.dll ฯลฯ)
---

# บทที่ 9 - การจัดการ Imports (Import Address Table - IAT)

โปรแกรมส่วนใหญ่บน Windows ไม่ได้ทำงานได้ด้วยตัวเองทั้งหมด แต่ต้องพึ่งพาฟังก์ชันและบริการต่างๆ ที่ระบบปฏิบัติการ (ผ่านทาง Kernel32.dll, User32.dll, Gdi32.dll ฯลฯ) หรือไลบรารีอื่นๆ (DLLs) จัดเตรียมไว้ให้ กระบวนการที่โปรแกรมเรียกใช้ฟังก์ชันจาก DLL ภายนอกนี้เรียกว่า **Dynamic Linking** และหัวใจสำคัญของกลไกนี้ใน PE format คือ **Import Table** และโดยเฉพาะอย่างยิ่ง **Import Address Table (IAT)**

การทำความเข้าใจว่าโปรแกรม imports (นำเข้า) ฟังก์ชันอะไรบ้างจาก DLL ใด เป็นขั้นตอนพื้นฐานและสำคัญอย่างยิ่งในการวิเคราะห์โปรแกรม โดยเฉพาะอย่างยิ่งในการวิเคราะห์มัลแวร์ เพราะรายการ imports มักจะเปิดเผย "ความสามารถ" (capabilities) ของมัลแวร์นั้นๆ เช่น สามารถติดต่อเครือข่าย, จัดการไฟล์, แก้ไข Registry, หรือสร้าง process ใหม่ได้หรือไม่

## 9.1 ภาพรวมของ Import Directory Table (IDT)

ข้อมูลเกี่ยวกับการ imports ทั้งหมดของ PE file ถูกจัดเก็บไว้ในโครงสร้างที่เรียกว่า **Import Directory Table (IDT)** (หรือบางครั้งก็เรียกว่า Import Descriptor Table) ตำแหน่งและขนาดของ IDT นี้ถูกชี้โดย Data Directory entry ตัวที่ 1 (`IMAGE_DIRECTORY_ENTRY_IMPORT`) ใน Optional Header

IDT คืออาร์เรย์ของโครงสร้าง `IMAGE_IMPORT_DESCRIPTOR` โดยแต่ละ entry ในอาร์เรย์นี้จะแทน DLL หนึ่งไฟล์ที่ PE image นี้ต้องการ import ฟังก์ชันเข้ามา อาร์เรย์นี้จะจบลงด้วย entry ที่มีค่าเป็น null ทั้งหมด (ทุกฟิลด์เป็น 0) เพื่อเป็นตัวบอกการสิ้นสุดของตาราง

**โครงสร้างของ `IMAGE_IMPORT_DESCRIPTOR` (แต่ละ entry มีขนาด 20 bytes):**

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)
    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;                           // RVA to DLL name (ASCII string)
    DWORD   FirstThunk;                     // RVA to IAT (PIMAGE_THUNK_DATA)
                                            // (If bound, this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

**คำอธิบายฟิลด์ที่สำคัญในแต่ละ `IMAGE_IMPORT_DESCRIPTOR`:**

1.  **`OriginalFirstThunk` (หรือ `Characteristics` ใน union):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยังอาร์เรย์ของ `IMAGE_THUNK_DATA` entries อาร์เรย์นี้มักถูกเรียกว่า **Import Lookup Table (ILT)** หรือบางครั้งก็เรียกว่า **Import Name Table (INT)** (เมื่อยังไม่ได้ถูก bound)
    *   **เนื้อหาใน ILT/INT:** แต่ละ `IMAGE_THUNK_DATA` entry ใน ILT/INT จะระบุฟังก์ชันหนึ่งๆ ที่ต้องการ import จาก DLL นี้ โดยอาจระบุด้วยชื่อฟังก์ชัน (ชี้ไปยัง `IMAGE_IMPORT_BY_NAME` structure) หรือด้วยหมายเลข ordinal
    *   **ความสำคัญ:** ILT/INT นี้จะ **ไม่ถูกแก้ไข** โดย Windows loader และจะยังคงเก็บข้อมูลดั้งเดิมว่าต้องการ import ฟังก์ชันอะไรบ้าง (โดยชื่อหรือ ordinal)
    *   **ถ้าเป็น 0:** หมายถึง entry นี้เป็นตัวจบอาร์เรย์ `IMAGE_IMPORT_DESCRIPTOR` (null terminator)

2.  **`TimeDateStamp` (DWORD - 4 bytes):**
    *   **ความหมาย:** เกี่ยวข้องกับการทำ **Binding** (การ resolve ที่อยู่ของ imported functions ล่วงหน้าตอน link time เพื่อให้โหลดเร็วขึ้น)
        *   **0:** ไม่ได้ bound หรือข้อมูล binding ไม่ถูกต้อง
        *   **-1 (0xFFFFFFFF):** DLL นี้ถูก bound แล้ว และ timestamp จริง (ถ้ามี) จะอยู่ใน Bound Import Table (`IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`)
        *   **ค่าอื่นๆ:** Timestamp ของ DLL ที่ถูก bound (วิธีเก่า, ไม่ค่อยใช้แล้ว)
    *   **ปัจจุบัน:** การทำ Binding ไม่ค่อยเป็นที่นิยมแล้ว เนื่องจาก ASLR ทำให้ `ImageBase` ของ DLLs ไม่แน่นอน ทำให้ข้อมูล binding ที่ทำไว้ล่วงหน้ามักจะใช้ไม่ได้ผล

3.  **`ForwarderChain` (DWORD - 4 bytes):**
    *   **ความหมาย:** เกี่ยวข้องกับการทำ **Function Forwarding** (เมื่อฟังก์ชันที่ import มาจาก DLL A จริงๆ แล้วถูก forward ไปยังฟังก์ชันใน DLL B)
        *   **-1 (0xFFFFFFFF):** ไม่มี forwarder สำหรับ DLL นี้
        *   **ค่าอื่นๆ:** Index เข้าไปใน `FirstThunk` array ที่ชี้ไปยัง forwarder แรก
    *   **การทำงาน:** ถ้า DLL A forward ฟังก์ชัน `FuncX` ไปยัง `FuncY` ใน DLL B, เมื่อโปรแกรมเรียก `FuncX` จาก DLL A, มันจะถูก redirect ไปเรียก `FuncY` จาก DLL B แทน
    *   **Cybersecurity Relevance:** มัลแวร์อาจใช้ forwarders เพื่อซ่อน API calls หรือทำให้การติดตาม API calls ยากขึ้น

4.  **`Name` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยังสตริง ASCII ที่มี null-terminated ซึ่งเป็น **ชื่อของ DLL** ที่จะ import ฟังก์ชันเข้ามา (เช่น "KERNEL32.DLL", "USER32.DLL")
    *   **Cybersecurity Relevance:** รายชื่อ DLLs ที่ import มาก็ให้เบาะแสเกี่ยวกับความสามารถของโปรแกรมได้ เช่น ถ้าเห็น "WS2_32.DLL" หรือ "WININET.DLL" แสดงว่าโปรแกรมมีการทำงานเกี่ยวกับเครือข่าย

5.  **`FirstThunk` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยังอาร์เรย์ของ `IMAGE_THUNK_DATA` entries เช่นกัน อาร์เรย์นี้คือ **Import Address Table (IAT)** ที่แท้จริง
    *   **ความสำคัญ:** **IAT นี้คือส่วนที่จะถูก Windows loader แก้ไข** ในระหว่างกระบวนการโหลดโปรแกรม loader จะทำการ resolve (ค้นหาที่อยู่จริง) ของแต่ละฟังก์ชันที่ import มา แล้วเขียน Virtual Address (VA) จริงของฟังก์ชันนั้นๆ ลงใน entry ที่สอดคล้องกันใน IAT
    *   **ก่อนการโหลด (Unbound):** IAT มักจะมีเนื้อหาเหมือนกับ ILT/INT (คือชี้ไปยังชื่อฟังก์ชันหรือ ordinal) หรืออาจจะชี้ไปยังตำแหน่งเดียวกันกับ ILT/INT เลยก็ได้ (ทำให้ ILT/INT ถูกเขียนทับเมื่อ IAT ถูก resolve, ซึ่งเป็นกรณีที่พบบ่อย)
    *   **หลังการโหลด (Resolved):** IAT จะเต็มไปด้วย Virtual Addresses ของฟังก์ชันที่ import มาจริงๆ
    *   **การเรียกใช้ฟังก์ชัน:** เมื่อโค้ดในโปรแกรมต้องการเรียกใช้ฟังก์ชันที่ import มา มันจะทำการ indirect call (เช่น `CALL [address_in_IAT]`) ผ่านทาง entry ที่สอดคล้องกันใน IAT นี้

## 9.2 โครงสร้าง `IMAGE_THUNK_DATA` และการระบุฟังก์ชัน

ทั้ง ILT/INT (`OriginalFirstThunk`) และ IAT (`FirstThunk`) ต่างก็เป็นอาร์เรย์ของโครงสร้าง `IMAGE_THUNK_DATA` (หรือ `IMAGE_THUNK_DATA32` / `IMAGE_THUNK_DATA64` ขึ้นอยู่กับว่าเป็น PE32 หรือ PE32+) อาร์เรย์นี้จะจบลงด้วย entry ที่มีค่าเป็น null (0)

**โครงสร้างของ `IMAGE_THUNK_DATA` (union ขนาดเท่า pointer, 4 bytes สำหรับ PE32, 8 bytes สำหรับ PE32+):**

```c
// สำหรับ PE32
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE
        DWORD Function;             // PVOID
        DWORD Ordinal;              // DWORD
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

// สำหรับ PE32+
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE
        ULONGLONG Function;         // PVOID
        ULONGLONG Ordinal;          // ULONGLONG
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;
```

**การตีความค่าใน `IMAGE_THUNK_DATA` (สำหรับ ILT/INT ก่อนการ resolve):**

แต่ละ entry ใน ILT/INT (และใน IAT ก่อน resolve) จะระบุฟังก์ชันที่ต้องการ import ด้วยวิธีใดวิธีหนึ่งจากสองวิธี โดยดูจากบิตสูงสุด (most significant bit - MSB) ของค่าใน `u1.Ordinal` (สำหรับ PE32) หรือ `u1.Ordinal` (สำหรับ PE32+):

1.  **Import by Ordinal:**
    *   **เงื่อนไข:** MSB ของ `u1.Ordinal` ถูกตั้งค่าเป็น 1 (เช่น `0x80000000` สำหรับ PE32)
    *   **การตีความ:** 16 บิตล่าง (least significant bits) ของ `u1.Ordinal` จะเป็น **หมายเลข ordinal** (เลขลำดับ) ของฟังก์ชันที่ต้องการ import จาก DLL นั้นๆ (ordinal คือหมายเลขประจำตัวของฟังก์ชันที่ export โดย DLL ซึ่งไม่ขึ้นกับชื่อ)
    *   **ข้อดี:** เล็กกว่าและเร็วกว่าการ import by name
    *   **ข้อเสีย:** ไม่ portable หาก DLL มีการเปลี่ยนแปลง ordinal ของฟังก์ชัน (ซึ่งไม่ควรเกิดขึ้นบ่อยสำหรับ public API)
    *   **Cybersecurity Relevance:** มัลแวร์บางตัวอาจ import by ordinal เพื่อทำให้การวิเคราะห์ยากขึ้น (เพราะไม่เห็นชื่อฟังก์ชันโดยตรง) หรือเพื่อ import undocumented API ที่ export โดย ordinal เท่านั้น

2.  **Import by Name:**
    *   **เงื่อนไข:** MSB ของ `u1.Ordinal` เป็น 0
    *   **การตีความ:** ค่าใน `u1.AddressOfData` จะเป็น **RVA** ที่ชี้ไปยังโครงสร้าง `IMAGE_IMPORT_BY_NAME`
    *   **โครงสร้าง `IMAGE_IMPORT_BY_NAME`:**
        ```c
        typedef struct _IMAGE_IMPORT_BY_NAME {
            WORD    Hint;        // อาจเป็น 0 หรือเป็น index เข้าไปใน Export Name Table ของ DLL (optional, for speed)
            CHAR    Name[1];     // ชื่อฟังก์ชัน (ASCII string, null-terminated)
                                 // Name[1] เป็นแค่ placeholder, ชื่อจะยาวต่อไปเรื่อยๆ
        } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
        ```
        *   `Hint`: เป็นคำใบ้ (optional) ที่ linker อาจใส่ไว้เพื่อช่วยให้ loader ค้นหาชื่อฟังก์ชันใน Export Table ของ DLL ได้เร็วขึ้น
        *   `Name`: คือชื่อฟังก์ชันที่ต้องการ import จริงๆ (เป็น null-terminated ASCII string)
    *   **ข้อดี:** Portable มากกว่า เพราะอ้างอิงด้วยชื่อ
    *   **ข้อเสีย:** ช้ากว่าเล็กน้อย และใช้พื้นที่มากกว่า
    *   **Cybersecurity Relevance:** การเห็นชื่อฟังก์ชันที่ import มาโดยตรง (เช่น "CreateRemoteThread", "WriteProcessMemory", "InternetOpenUrlA") จะให้ข้อมูลที่ชัดเจนเกี่ยวกับพฤติกรรมของมัลแวร์

**ลำดับการทำงานของ Loader ในการ resolve IAT:**

สำหรับแต่ละ `IMAGE_IMPORT_DESCRIPTOR` (แต่ละ DLL):
1.  Loader โหลด DLL ที่ระบุโดย `Name` field เข้าสู่ memory (ถ้ายังไม่ได้โหลด)
2.  Loader วนลูปผ่าน entries ใน ILT/INT (ที่ชี้โดย `OriginalFirstThunk`) และ IAT (ที่ชี้โดย `FirstThunk`) พร้อมกัน (มักจะใช้ ILT/INT เป็นตัวนำ)
3.  สำหรับแต่ละฟังก์ชัน:
    *   ถ้า import by ordinal: Loader ค้นหาฟังก์ชันใน Export Table ของ DLL ด้วยหมายเลข ordinal นั้น
    *   ถ้า import by name: Loader ค้นหาฟังก์ชันใน Export Table ของ DLL ด้วยชื่อฟังก์ชันที่อยู่ใน `IMAGE_IMPORT_BY_NAME`
4.  เมื่อพบที่อยู่ (VA) ของฟังก์ชันใน DLL ที่โหลดแล้ว Loader จะเขียน VA นั้นทับลงใน entry ที่ **สอดคล้องกันใน IAT**

หลังจากกระบวนการนี้เสร็จสิ้น IAT จะเต็มไปด้วย Virtual Addresses ที่ถูกต้องของฟังก์ชันที่ import มาทั้งหมด และโปรแกรมก็พร้อมที่จะเรียกใช้ฟังก์ชันเหล่านั้นผ่านทาง IAT

## 9.3 การทำงานของ Import Address Table (IAT)

IAT คือหัวใจสำคัญที่ทำให้โค้ดใน PE file สามารถเรียกใช้ฟังก์ชันจาก DLL อื่นได้
*   **Indirect Call:** เมื่อคอมไพเลอร์สร้างโค้ดที่เรียกฟังก์ชัน import มันไม่ได้ hardcode address ของฟังก์ชันนั้นโดยตรง (เพราะยังไม่รู้ address จนกว่าจะ runtime) แต่จะสร้างโค้ดที่ทำการ **indirect call** ผ่านทาง pointer ที่อยู่ใน IAT
    *   ตัวอย่าง (Assembly x86):
        ```assembly
        ; สมมติว่า MessageBoxA ถูก import และ IAT entry ของมันอยู่ที่ RVA 0x12340
        ; และ ImageBase คือ 0x400000
        ; ดังนั้น IAT entry สำหรับ MessageBoxA อยู่ที่ VA 0x412340
        ; ... setup arguments for MessageBoxA ...
        CALL DWORD PTR [0x412340] ; เรียก MessageBoxA ผ่าน IAT
        ```
*   **Loader เป็นผู้เติม IAT:** Windows loader มีหน้าที่เติม Virtual Addresses ที่ถูกต้องลงใน IAT ตอนที่โปรแกรมถูกโหลด
*   **IAT Hooking:** เนื่องจากทุกการเรียก API ที่ import มาจะต้องผ่าน IAT, IAT จึงเป็นเป้าหมายยอดนิยมสำหรับการทำ **hooking**
    *   **API Hooking คืออะไร?** คือการแก้ไข address ใน IAT (หรือที่อื่น) ให้ชี้ไปยังฟังก์ชันของเราเอง (hook function) แทนที่จะเป็น API เดิม เมื่อโปรแกรมเรียก API นั้น มันจะเรียก hook function ของเราแทน hook function สามารถทำอะไรบางอย่าง (เช่น log การเรียก, ปรับเปลี่ยน arguments, บล็อกการเรียก) แล้วค่อยเรียก API เดิม (ถ้าต้องการ)
    *   **ใครใช้ IAT Hooking?**
        *   **Antivirus/Security Software:** เพื่อดักจับ API calls ที่น่าสงสัย หรือเพื่อ monitor พฤติกรรมของ process
        *   **Malware:** เพื่อหลบเลี่ยงการตรวจจับ (เช่น hook API ที่ใช้ตรวจจับมัลแวร์ให้ส่งคืนค่าปลอม), เพื่อดักข้อมูล (เช่น hook API ที่เกี่ยวกับ network เพื่อดักจับ passwords), หรือเพื่อ inject โค้ด
        *   **Debugging/Instrumentation Tools:** เพื่อติดตามการเรียก API

## 9.4 การวิเคราะห์ Imports ในงาน Cybersecurity

การตรวจสอบรายการ imports ของ PE file เป็นหนึ่งในขั้นตอนแรกๆ และสำคัญที่สุดของการวิเคราะห์มัลแวร์แบบ static:

1.  **ระบุความสามารถ (Capabilities):**
    *   **Networking:** Imports จาก `ws2_32.dll` (socket functions), `wininet.dll` (HTTP functions), `urlmon.dll` บ่งชี้ถึงการสื่อสารผ่านเครือข่าย (C&C, download/upload)
    *   **File System:** Imports จาก `kernel32.dll` เช่น `CreateFile`, `WriteFile`, `DeleteFile` บ่งชี้ถึงการจัดการไฟล์ (สร้าง/ลบ/แก้ไขไฟล์, แพร่กระจาย)
    *   **Process Manipulation:** Imports เช่น `CreateProcess`, `OpenProcess`, `WriteProcessMemory`, `CreateRemoteThread` บ่งชี้ถึงความสามารถในการสร้าง/ควบคุม process อื่น (process injection, hollowing)
    *   **Registry:** Imports เช่น `RegCreateKey`, `RegSetValue`, `RegDeleteValue` บ่งชี้ถึงการแก้ไข Registry (persistence, configuration)
    *   **Cryptography:** Imports จาก `advapi32.dll` (CryptoAPI) หรือ `bcrypt.dll` บ่งชี้ถึงการใช้การเข้ารหัส/ถอดรหัส (อาจเป็น ransomware หรือการเข้ารหัส C&C traffic)
    *   **Anti-Analysis/Evasion:** Imports เช่น `IsDebuggerPresent`, `GetTickCount`, `Sleep`, `VirtualAllocEx`, `VirtualProtectEx` อาจถูกใช้ในเทคนิค anti-debugging, anti-VM, หรือการ unpack โค้ด
    *   **Keystroke Logging/Spying:** Imports จาก `user32.dll` เช่น `SetWindowsHookEx`, `GetAsyncKeyState`, `GetForegroundWindow` อาจบ่งชี้ถึงการดักจับ keystrokes หรือการสอดแนมผู้ใช้

2.  **ระบุ DLLs ที่น่าสงสัย:**
    *   การ import จาก DLLs ที่ไม่ค่อยพบเห็น หรือ DLLs ที่มีชื่อแปลกๆ อาจเป็นที่น่าสนใจ
    *   บางครั้งมัลแวร์อาจ drop DLL ของตัวเองแล้ว import ฟังก์ชันจาก DLL นั้น

3.  **Import by Ordinal:**
    *   หากพบการ import by ordinal จำนวนมาก ควรพยายาม resolve ordinal เหล่านั้นให้เป็นชื่อฟังก์ชัน (ถ้าทำได้) เพื่อทำความเข้าใจว่ากำลังเรียก API อะไร
    *   เครื่องมือ PE analysis หลายตัวสามารถทำสิ่งนี้ได้โดยอัตโนมัติ (โดยดูจาก export table ของ well-known DLLs)

4.  **Import Table ที่เล็กผิดปกติ หรือไม่มีเลย:**
    *   **Packers/Obfuscators:** มัลแวร์ที่ถูก pack มักจะมี Import Table ที่เล็กมาก (อาจมีแค่ `LoadLibrary` และ `GetProcAddress` จาก `kernel32.dll`) เพราะว่าตัว unpacker stub จะทำการ resolve API ที่ต้องการใช้ใน runtime เอง (dynamic API resolution) โดยไม่ผ่าน Import Table แบบปกติ
    *   **Shellcode/Position-Independent Code:** โค้ดบางประเภท (เช่น shellcode ที่ถูก inject) อาจไม่มี Import Table เลย และจะ resolve API ด้วยเทคนิคอื่น (เช่น เดิน PEB/TEB เพื่อหา `kernel32.dll` base address แล้วค้นหา `LoadLibrary`/`GetProcAddress` เอง)

5.  **เครื่องมือ:**
    *   PE Viewers (PE-bear, CFF Explorer, Pestudio) จะแสดงรายการ imports อย่างละเอียด
    *   Disassemblers (IDA Pro, Ghidra, x64dbg) จะแสดง cross-references ไปยัง API calls ในโค้ด
    *   YARA rules สามารถใช้ตรวจจับ patterns ของ imports ที่น่าสงสัยได้

## 9.5 สรุป

Import Directory Table (IDT), Import Lookup Table (ILT/INT), และที่สำคัญที่สุดคือ Import Address Table (IAT) เป็นกลไกหลักที่ทำให้ PE files สามารถเรียกใช้ฟังก์ชันจาก DLL ภายนอกได้ Windows loader มีหน้าที่ resolve ที่อยู่ของ imported functions และเติมลงใน IAT ณ runtime

สำหรับนักวิเคราะห์ Cybersecurity, การตรวจสอบรายการ imports ให้ข้อมูลเชิงลึกที่สำคัญเกี่ยวกับพฤติกรรมและความสามารถของโปรแกรม และเป็นจุดเริ่มต้นที่ยอดเยี่ยมในการทำความเข้าใจมัลแวร์ การสังเกต DLLs ที่ import, ฟังก์ชันที่เรียกใช้, การใช้ import by ordinal, หรือลักษณะที่ผิดปกติของ Import Table สามารถเปิดโปงเทคนิคที่มัลแวร์ใช้ในการทำงาน, ซ่อนตัว, หรือหลบเลี่ยงการตรวจจับได้

ในบทต่อไป เราจะดูด้านตรงข้ามของการ imports นั่นคือ **การจัดการ Exports (Export Address Table - EAT)** ซึ่งเกี่ยวข้องกับการที่ DLL ให้บริการฟังก์ชันแก่โปรแกรมอื่น
