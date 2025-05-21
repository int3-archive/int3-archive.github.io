---
date: 2025-01-10
title: PE Format บทที่ 10 - การจัดการ Exports (Export Address Table - EAT)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: Export Table (หรือ Export Directory Table) จะอธิบายว่า PE file (โดยเฉพาะ DLL) ให้บริการ (export) ฟังก์ชันและ/หรือข้อมูลอะไรบ้างแก่โปรแกรมหรือ DLL อื่นๆ
---

# บทที่ 10 - การจัดการ Exports (Export Address Table - EAT)

ในขณะที่ Import Table (บทที่ 9) อธิบายว่า PE file หนึ่งๆ *เรียกใช้* ฟังก์ชันจาก DLL ภายนอกอย่างไร **Export Table** (หรือ Export Directory Table) จะอธิบายว่า PE file (โดยเฉพาะ DLL) *ให้บริการ* (export) ฟังก์ชันและ/หรือข้อมูลอะไรบ้างแก่โปรแกรมหรือ DLL อื่นๆ

ไฟล์ Executable (.EXE) ส่วนใหญ่ **ไม่** export ฟังก์ชันใดๆ (ยกเว้นกรณีพิเศษบางอย่าง) ดังนั้น Export Table มักจะพบและมีความสำคัญอย่างยิ่งในไฟล์ Dynamic-Link Library (.DLL) รวมถึงไฟล์อื่นๆ ที่มีลักษณะคล้าย DLL เช่น .SYS (drivers), .OCX (ActiveX controls)

การทำความเข้าใจ Export Table ช่วยให้เราทราบว่า DLL นั้นๆ มี "ประตู" อะไรบ้างที่เปิดให้โค้ดภายนอกเข้ามาเรียกใช้งาน ซึ่งเป็นข้อมูลสำคัญทั้งสำหรับนักพัฒนาที่ต้องการใช้ DLL นั้น และสำหรับนักวิเคราะห์ Cybersecurity ที่ต้องการทำความเข้าใจบทบาทของ DLL ต้องสงสัย

## 10.1 ภาพรวมของ Export Directory Table

ข้อมูลเกี่ยวกับการ exports ทั้งหมดของ PE file ถูกจัดเก็บไว้ในโครงสร้างที่เรียกว่า **Export Directory Table** ตำแหน่งและขนาดของตารางนี้ถูกชี้โดย Data Directory entry ตัวที่ 0 (`IMAGE_DIRECTORY_ENTRY_EXPORT`) ใน Optional Header

Export Directory Table เป็นโครงสร้าง `IMAGE_EXPORT_DIRECTORY` เดียว ซึ่งประกอบด้วยฟิลด์ที่ชี้ไปยังอาร์เรย์อื่นๆ ที่เก็บรายละเอียดของฟังก์ชันและชื่อที่ export

**โครงสร้างของ `IMAGE_EXPORT_DIRECTORY` (ขนาด 40 bytes):**

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;        // Reserved, must be 0
    DWORD   TimeDateStamp;          // Timestamp of when the export data was created
    WORD    MajorVersion;           // Major version number of the export data
    WORD    MinorVersion;           // Minor version number of the export data
    DWORD   Name;                   // RVA of the ASCII string that contains the name of the DLL
    DWORD   Base;                   // Starting ordinal number for exports in this image (usually 1)
    DWORD   NumberOfFunctions;      // Total number of functions exported by this DLL (size of EAT)
    DWORD   NumberOfNames;          // Number of functions exported by name (size of ENPT and EOT)
                                    // This can be less than NumberOfFunctions
    DWORD   AddressOfFunctions;     // RVA to the Export Address Table (EAT)
    DWORD   AddressOfNames;         // RVA to the Export Name Pointer Table (ENPT)
    DWORD   AddressOfNameOrdinals;  // RVA to the Export Ordinal Table (EOT)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

**คำอธิบายฟิลด์ที่สำคัญใน `IMAGE_EXPORT_DIRECTORY`:**

1.  **`Characteristics` (DWORD - 4 bytes):**
    *   **ความหมาย:** สงวนไว้ (reserved) และควรมีค่าเป็น 0
    *   **Cybersecurity Relevance:** ถ้าไม่เป็น 0 อาจเป็นสัญญาณของความผิดปกติ

2.  **`TimeDateStamp` (DWORD - 4 bytes):**
    *   **ความหมาย:** Timestamp (จำนวนวินาทีนับจาก 1 มกราคม 1970 UTC) ที่ระบุเวลาที่ข้อมูล export นี้ถูกสร้างขึ้นโดย linker โดยทั่วไปจะเหมือนกับ `TimeDateStamp` ใน COFF File Header
    *   **Cybersecurity Relevance:** การปลอมแปลง timestamp นี้ (timestomping) สามารถทำได้

3.  **`MajorVersion` (WORD - 2 bytes) และ `MinorVersion` (WORD - 2 bytes):**
    *   **ความหมาย:** เวอร์ชัน (Major.Minor) ของข้อมูล export นี้ ผู้พัฒนาสามารถตั้งค่าได้ (มักจะสอดคล้องกับเวอร์ชันของ DLL)
    *   **Cybersecurity Relevance:** ไม่ค่อยมีนัยยะสำคัญทาง security โดยตรง

4.  **`Name` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยังสตริง ASCII ที่มี null-terminated ซึ่งเป็น **ชื่อภายใน (internal name) ของ DLL** นี้เอง ชื่อนี้ไม่จำเป็นต้องตรงกับชื่อไฟล์บนดิสก์เสมอไป
    *   **ตัวอย่าง:** สำหรับ `kernel32.dll` ชื่อนี้อาจเป็น "KERNEL32.dll"
    *   **Cybersecurity Relevance:** ชื่อ DLL ที่แปลกประหลาดหรือไม่สอดคล้องกับชื่อไฟล์ อาจเป็นที่น่าสนใจ

5.  **`Base` (DWORD - 4 bytes):**
    *   **ความหมาย:** หมายเลข ordinal **เริ่มต้น** สำหรับฟังก์ชันที่ถูก export โดย DLL นี้ โดยทั่วไปค่านี้คือ **1** ซึ่งหมายความว่า ordinal แรกที่ใช้คือ 1, ordinal ที่สองคือ 2, وهكذا.
    *   **การคำนวณ Ordinal จริง:** Ordinal ที่เก็บใน Export Ordinal Table (EOT) จะเป็น 0-based index เมื่อต้องการหา ordinal จริงที่ใช้ในการ import by ordinal จะต้องนำค่าจาก EOT มาบวกกับ `Base` นี้
    *   **Cybersecurity Relevance:** `Base` ที่ไม่ใช่ 1 อาจเป็นเทคนิคทำให้การ map ordinal ไปยังฟังก์ชันสับสนเล็กน้อย แต่ไม่ค่อยพบ

6.  **`NumberOfFunctions` (DWORD - 4 bytes):**
    *   **ความหมาย:** **จำนวนรวม** ของฟังก์ชันและ/หรือข้อมูลที่ถูก export โดย DLL นี้ ไม่ว่าจะเป็นการ export by name หรือ by ordinal only จำนวนนี้คือขนาด (จำนวน entries) ของ Export Address Table (EAT)
    *   **Cybersecurity Relevance:** จำนวนฟังก์ชันที่ export มากผิดปกติสำหรับ DLL ที่ไม่ควรมี exports มากนัก หรือน้อยผิดปกติสำหรับ system DLL ที่ควรมี exports มากมาย อาจเป็นสัญญาณที่น่าสนใจ

7.  **`NumberOfNames` (DWORD - 4 bytes):**
    *   **ความหมาย:** จำนวนของฟังก์ชันที่ถูก export **โดยใช้ชื่อ** (named exports) จำนวนนี้คือขนาด (จำนวน entries) ของ Export Name Pointer Table (ENPT) และ Export Ordinal Table (EOT)
    *   **ความสัมพันธ์กับ `NumberOfFunctions`:** `NumberOfNames` จะต้องน้อยกว่าหรือเท่ากับ `NumberOfFunctions` เสมอ
        *   ถ้า `NumberOfNames` < `NumberOfFunctions` หมายความว่ามีบางฟังก์ชันที่ถูก export โดย ordinal เท่านั้น (ไม่มีชื่อ)
        *   ถ้า `NumberOfNames` == 0 หมายความว่าทุกฟังก์ชันถูก export โดย ordinal เท่านั้น (หรือ DLL ไม่ export อะไรเลยถ้า `NumberOfFunctions` ก็เป็น 0)
    *   **Cybersecurity Relevance:** DLL ที่ export ฟังก์ชันสำคัญๆ โดย ordinal only (ทำให้ `NumberOfNames` น้อยกว่า `NumberOfFunctions` มาก) อาจเป็นเทคนิคของมัลแวร์เพื่อซ่อนชื่อฟังก์ชันที่เป็นอันตราย

8.  **`AddressOfFunctions` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยัง **Export Address Table (EAT)**
    *   **EAT:** คืออาร์เรย์ของ DWORDs (สำหรับ PE32) หรือ QWORDs (สำหรับ PE32+) แต่ละ entry ใน EAT คือ **RVA ของฟังก์ชันที่ถูก export** (หรือ RVA ของข้อมูลที่ถูก export) หรือเป็น **RVA ของ forwarder string** (ถ้าฟังก์ชันนั้นถูก forward)
    *   **การ Index EAT:** EAT ถูก index โดยใช้ ordinal (หลังจากปรับด้วย `Base` แล้ว)

9.  **`AddressOfNames` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยัง **Export Name Pointer Table (ENPT)**
    *   **ENPT:** คืออาร์เรย์ของ DWORDs แต่ละ entry ใน ENPT คือ **RVA ของสตริงชื่อฟังก์ชันที่ถูก export** (ASCII, null-terminated) ชื่อใน ENPT นี้จะถูกเรียงตามลำดับตัวอักษร (alphabetical order) เพื่อให้สามารถค้นหาแบบ binary search ได้
    *   **การ Index ENPT:** ENPT ถูก index จาก 0 ถึง `NumberOfNames` - 1

10. **`AddressOfNameOrdinals` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยัง **Export Ordinal Table (EOT)**
    *   **EOT:** คืออาร์เรย์ของ WORDs (2 bytes) แต่ละ entry ใน EOT คือ **0-based ordinal index** ที่สอดคล้องกับชื่อฟังก์ชันใน ENPT ณ ตำแหน่ง index เดียวกัน
    *   **การทำงานร่วมกับ ENPT:** เมื่อต้องการค้นหาฟังก์ชันด้วยชื่อ:
        1.  ค้นหาชื่อใน ENPT (ซึ่งเรียงตามตัวอักษร) เพื่อหา index `i` ของชื่อนั้น
        2.  ใช้ index `i` เดียวกันนี้ไปอ่านค่าจาก EOT[i] จะได้ 0-based ordinal `o`
        3.  ใช้ 0-based ordinal `o` นี้เป็น index เข้าไปใน EAT (คือ EAT[o]) เพื่อหา RVA ของฟังก์ชัน
    *   **การ Index EOT:** EOT ถูก index จาก 0 ถึง `NumberOfNames` - 1

## 10.2 ตารางย่อยที่เกี่ยวข้องกับ Exports

`IMAGE_EXPORT_DIRECTORY` ชี้ไปยังตารางย่อยอีก 3 ตารางที่มีบทบาทสำคัญ:

1.  **Export Address Table (EAT):**
    *   **ชี้โดย:** `AddressOfFunctions`
    *   **ขนาด:** `NumberOfFunctions` entries
    *   **แต่ละ Entry:** เป็น DWORD (RVA)
        *   **กรณีปกติ:** RVA ของโค้ดฟังก์ชันที่ถูก export หรือ RVA ของข้อมูลที่ถูก export
        *   **กรณี Forwarder:** RVA ของ "forwarder string" ซึ่งมีรูปแบบเป็น "OtherDLLName.ExportedName" หรือ "OtherDLLName.#Ordinal" Loader จะทำการ resolve forwarder นี้ต่อไป
    *   **การเข้าถึง:** สามารถเข้าถึง EAT ได้โดยตรงด้วย ordinal (ordinal ที่ถูกปรับด้วย `Base` แล้ว ลบ `Base` อีกทีเพื่อให้เป็น 0-based index เข้า EAT)

2.  **Export Name Pointer Table (ENPT):**
    *   **ชี้โดย:** `AddressOfNames`
    *   **ขนาด:** `NumberOfNames` entries
    *   **แต่ละ Entry:** เป็น DWORD (RVA) ที่ชี้ไปยังสตริงชื่อฟังก์ชัน (ASCII, null-terminated)
    *   **การเรียงลำดับ:** ชื่อใน ENPT **ต้อง** เรียงตามลำดับตัวอักษร (case-sensitive)

3.  **Export Ordinal Table (EOT):**
    *   **ชี้โดย:** `AddressOfNameOrdinals`
    *   **ขนาด:** `NumberOfNames` entries
    *   **แต่ละ Entry:** เป็น WORD (2 bytes) ซึ่งเป็น 0-based ordinal index ที่จะใช้เข้าถึง EAT
    *   **ความสัมพันธ์:** EOT[i] ให้ ordinal สำหรับชื่อที่ ENPT[i] ชี้ไป

**กระบวนการที่ Loader ค้นหา Exported Function (Lookup Process):**

เมื่อโปรแกรม A ต้องการ import ฟังก์ชัน `FuncX` จาก DLL B:

*   **ถ้า Import by Name ("FuncX"):**
    1.  Loader ไปที่ `IMAGE_EXPORT_DIRECTORY` ของ DLL B
    2.  ค้นหาชื่อ "FuncX" ใน ENPT (ที่ชี้โดย `AddressOfNames`) เนื่องจาก ENPT เรียงตามตัวอักษร Loader สามารถใช้ binary search เพื่อหา index `i` ของ "FuncX" ได้อย่างรวดเร็ว
    3.  ถ้าพบชื่อ "FuncX" ที่ ENPT[i], Loader จะไปอ่านค่า ordinal `o` จาก EOT[i]
    4.  Loader ใช้ ordinal `o` นี้ (ซึ่งเป็น 0-based index) ไปอ่าน RVA จาก EAT[o] (ที่ชี้โดย `AddressOfFunctions`)
    5.  RVA ที่ได้จาก EAT[o] คือ RVA ของ `FuncX` ใน DLL B (หรือ RVA ของ forwarder string)
    6.  Loader นำ RVA นี้บวกกับ `ImageBase` ของ DLL B (ที่โหลดเข้า memory แล้ว) เพื่อให้ได้ Virtual Address (VA) จริงของ `FuncX`
    7.  VA นี้จะถูกเขียนลงใน IAT ของโปรแกรม A

*   **ถ้า Import by Ordinal (เช่น ordinal #5):**
    1.  Loader ไปที่ `IMAGE_EXPORT_DIRECTORY` ของ DLL B
    2.  แปลง ordinal ที่ต้องการ (เช่น 5) ให้เป็น 0-based index โดยลบค่า `Base` (จาก `IMAGE_EXPORT_DIRECTORY`) ออก (เช่น ถ้า `Base` = 1, index คือ 5 - 1 = 4) ให้เป็น `o_idx`
    3.  ตรวจสอบว่า `o_idx` อยู่ในช่วงที่ถูกต้อง (0 ถึง `NumberOfFunctions` - 1)
    4.  ถ้าถูกต้อง, Loader ไปอ่าน RVA จาก EAT[o_idx]
    5.  ขั้นตอนที่เหลือเหมือนกับการ import by name (หา VA, เขียนลง IAT)

**Forwarded Exports:**
*   ถ้า RVA ที่ได้จาก EAT ชี้ไปยังตำแหน่งที่อยู่ในช่วง RVA ของ export section เอง (คือระหว่าง RVA ของ `IMAGE_EXPORT_DIRECTORY` และ RVA + ขนาดของ export section ทั้งหมด) นั่นหมายความว่า RVA นั้นชี้ไปยัง "forwarder string" ไม่ใช่โค้ดฟังก์ชัน
*   Forwarder string จะมีรูปแบบ "DLL_NAME.FUNCTION_NAME" (เช่น "NTDLL.RtlAllocateHeap") หรือ "DLL_NAME.#ORDINAL" (เช่น "NTDLL.#123")
*   Loader จะทำการ import `FUNCTION_NAME` หรือ `#ORDINAL` จาก `DLL_NAME` นั้นอีกทอดหนึ่ง
*   **Cybersecurity Relevance:** Forwarding สามารถใช้เป็นเทคนิคซ่อน API หรือ redirect การเรียกไปยัง DLL อื่น ซึ่งมัลแวร์อาจใช้ประโยชน์ได้ การวิเคราะห์ call chain ที่มี forwarders จึงสำคัญ

## 10.3 การ Export โดยไม่มีชื่อ (Ordinal-Only Exports)

DLL สามารถ export ฟังก์ชันโดยไม่จำเป็นต้องมีชื่อได้ (export by ordinal only) ในกรณีนี้:
*   ฟังก์ชันนั้นจะมี entry ใน EAT (ที่ `NumberOfFunctions` นับรวม)
*   แต่จะ **ไม่มี** entry ที่สอดคล้องกันใน ENPT และ EOT (ดังนั้น `NumberOfNames` จะไม่นับฟังก์ชันนี้)
*   โปรแกรมที่ต้องการใช้ฟังก์ชันนี้ จะต้อง import by ordinal เท่านั้น

**สาเหตุที่ทำ Ordinal-Only Exports:**
*   **ลดขนาด DLL:** การไม่เก็บชื่อช่วยประหยัดพื้นที่เล็กน้อย
*   **Obscurity:** ทำให้การค้นหาหรือทำความเข้าใจฟังก์ชันนั้นยากขึ้นเล็กน้อย (ต้องรู้ ordinal)
*   **Undocumented APIs:** Microsoft (และผู้พัฒนารายอื่น) อาจ export บางฟังก์ชันที่เป็น internal หรือ undocumented โดยใช้ ordinal only เพื่อไม่ให้คนทั่วไปเรียกใช้โดยตรงผ่านชื่อ (แต่ก็ยังสามารถถูกเรียกได้ถ้าทราบ ordinal)

**Cybersecurity Relevance:**
*   มัลแวร์ DLL มักจะ export ฟังก์ชันที่เป็นอันตรายหรือฟังก์ชัน C&C โดยใช้ ordinal only เพื่อหลีกเลี่ยงการถูกตรวจจับด้วยชื่อฟังก์ชันที่น่าสงสัย
*   การวิเคราะห์ DLL ที่มี `NumberOfFunctions` มากกว่า `NumberOfNames` อย่างมีนัยสำคัญ ควรตรวจสอบว่าฟังก์ชันที่ export by ordinal only นั้นทำอะไรบ้าง

## 10.4 การวิเคราะห์ Exports ในงาน Cybersecurity

การตรวจสอบ Export Table ของ DLL เป็นสิ่งสำคัญในการวิเคราะห์มัลแวร์:

1.  **ระบุบทบาทของ DLL:**
    *   ชื่อฟังก์ชันที่ export บอกถึงหน้าที่หลักของ DLL นั้นๆ
    *   เช่น DLL ที่ export ฟังก์ชันเกี่ยวกับการเข้ารหัส อาจเป็นส่วนหนึ่งของ ransomware
    *   DLL ที่ export ฟังก์ชันเกี่ยวกับการจัดการเครือข่าย อาจเป็น C&C module

2.  **ค้นหาฟังก์ชันที่เป็นอันตราย:**
    *   ชื่อฟังก์ชันที่บ่งบอกถึงพฤติกรรมที่เป็นอันตราย (เช่น "StartKeylogger", "SendDataToC2", "EncryptFileSystem")
    *   การ export ฟังก์ชันที่มีชื่อคล้ายกับ API ของ Windows แต่มีพฤติกรรมต่างกัน (API spoofing)

3.  **ตรวจสอบ Ordinal-Only Exports:**
    *   ใช้เครื่องมือ PE analysis เพื่อแสดงรายการฟังก์ชันทั้งหมดที่ export (รวมถึง ordinal-only) และพยายาม reverse engineer ฟังก์ชันเหล่านั้น
    *   มัลแวร์ DLL จำนวนมาก (เช่น RATs, backdoors) จะ export ฟังก์ชันหลักๆ (เช่น command handler) โดยใช้ ordinal

4.  **Forwarded Exports ที่น่าสงสัย:**
    *   การ forward ไปยัง DLL ที่ไม่เกี่ยวข้อง หรือไปยังฟังก์ชันที่ไม่ควรถูกเรียกโดยตรง อาจเป็นเทคนิคหลอกลวง
    *   บางครั้ง malware อาจ forward API call ไปยัง DLL ของตัวเองอีกตัวหนึ่ง

5.  **Export Table ที่ว่างเปล่า หรือไม่มีเลย ใน DLL:**
    *   ถ้า DLL ควรจะมี exports แต่กลับไม่มี หรือ Export Table ชี้ไปยังข้อมูลที่ไม่ถูกต้อง แสดงว่า DLL อาจเสียหาย ถูก pack หรือเป็นส่วนหนึ่งของเทคนิค anti-analysis
    *   บาง packers จะทำการสร้าง Export Table ขึ้นใหม่ใน memory หลังจาก unpack

6.  **ชื่อ DLL ภายใน (`Name` field ใน `IMAGE_EXPORT_DIRECTORY`):**
    *   ถ้าชื่อนี้ไม่ตรงกับชื่อไฟล์จริง หรือเป็นชื่อที่แปลกประหลาด อาจเป็นเบาะแส
    *   บางครั้งมัลแวร์อาจใช้ชื่อ DLL ที่เหมือนกับ system DLL เพื่อหลอกผู้ใช้หรือเครื่องมือ

7.  **เครื่องมือ:**
    *   PE Viewers (PE-bear, CFF Explorer, Pestudio) จะแสดงรายการ exports อย่างละเอียด รวมถึงการ resolve forwarders และ ordinal-only exports (ถ้าทำได้)
    *   Disassemblers (IDA Pro, Ghidra) จะช่วยให้สามารถกระโดดไปยังโค้ดของฟังก์ชันที่ export ได้โดยตรง และวิเคราะห์การทำงานของมัน

## 10.5 สรุป

Export Directory Table เป็นโครงสร้างหลักที่ DLL (และ PE file อื่นๆ ที่ทำหน้าที่คล้าย DLL) ใช้ในการประกาศฟังก์ชันและข้อมูลที่พร้อมให้โปรแกรมภายนอกเรียกใช้งาน ประกอบด้วย `IMAGE_EXPORT_DIRECTORY` ที่ชี้ไปยังตารางย่อยคือ Export Address Table (EAT), Export Name Pointer Table (ENPT), และ Export Ordinal Table (EOT) ซึ่งทำงานร่วมกันเพื่อให้ loader สามารถค้นหาที่อยู่ของฟังก์ชันที่ export ได้ ทั้งโดยชื่อและโดย ordinal

สำหรับนักวิเคราะห์ Cybersecurity, Export Table เป็นขุมทรัพย์ข้อมูลที่สำคัญในการทำความเข้าใจวัตถุประสงค์และพฤติกรรมของ DLL ต้องสงสัย การวิเคราะห์ชื่อฟังก์ชัน, การตรวจสอบ ordinal-only exports, และการติดตาม forwarders สามารถเปิดเผยกลไกการทำงานของมัลแวร์ได้อย่างมาก

ในบทต่อไป เราจะไปดูกันที่ **ทรัพยากร (Resources) ใน PE File** ซึ่งเป็นอีกส่วนหนึ่งที่มัลแวร์มักใช้ในการซ่อนข้อมูลหรือ payloads
