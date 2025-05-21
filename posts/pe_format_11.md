---
date: 2025-01-11
title: PE Format บทที่ 11 - ทรัพยากร (Resources) ใน PE File
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: นอกเหนือจากโค้ดที่ประมวลผลได้ (executable code) และข้อมูล (data) แล้ว PE file ยังสามารถบรรจุสิ่งที่เรียกว่า ทรัพยากร (Resources) ได้อีกด้วย
---

# บทที่ 11 - ทรัพยากร (Resources) ใน PE File

นอกเหนือจากโค้ดที่ประมวลผลได้ (executable code) และข้อมูล (data) แล้ว PE file ยังสามารถบรรจุสิ่งที่เรียกว่า **ทรัพยากร (Resources)** ได้อีกด้วย ทรัพยากรเหล่านี้เป็นข้อมูลที่ไม่ใช่โค้ดโดยตรง แต่เป็นส่วนเสริมที่โปรแกรมใช้งาน เช่น ไอคอน, เคอร์เซอร์, รูปภาพ, เสียง, สตริงข้อความ (สำหรับหลายภาษา), เมนู, ไดอะล็อกบ็อกซ์, ข้อมูลเวอร์ชัน, และแม้แต่ข้อมูลไบนารีที่กำหนดเอง

การจัดเก็บทรัพยากรภายใน PE file ช่วยให้โปรแกรมมีความสมบูรณ์ในตัวเอง (self-contained) และง่ายต่อการจัดการ โดยเฉพาะอย่างยิ่งสำหรับการทำ Localization (การปรับโปรแกรมให้เข้ากับภาษาและวัฒนธรรมท้องถิ่น) หรือการปรับเปลี่ยนรูปลักษณ์ของโปรแกรมโดยไม่ต้องคอมไพล์โค้ดใหม่

สำหรับนักวิเคราะห์ Cybersecurity, ส่วนของทรัพยากรเป็นอีกจุดหนึ่งที่น่าสนใจ เพราะมัลแวร์มักใช้เป็นที่ซ่อนข้อมูล, payloads ที่เข้ารหัส, configuration, หรือแม้แต่ PE file อื่นๆ

## 11.1 ภาพรวมของ Resource Directory Table

ข้อมูลทรัพยากรทั้งหมดใน PE file ถูกจัดระเบียบในโครงสร้างแบบต้นไม้ (tree-like structure) โดยมีจุดเริ่มต้นที่ **Resource Directory Table** ตำแหน่งและขนาดของตารางนี้ (ซึ่งเป็น root ของ resource tree) ถูกชี้โดย Data Directory entry ตัวที่ 2 (`IMAGE_DIRECTORY_ENTRY_RESOURCE`) ใน Optional Header

โครงสร้างหลักที่ใช้ในการจัดระเบียบทรัพยากรคือ `IMAGE_RESOURCE_DIRECTORY` และ `IMAGE_RESOURCE_DIRECTORY_ENTRY`

**โครงสร้างของ `IMAGE_RESOURCE_DIRECTORY` (ขนาด 16 bytes):**

```c
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD   Characteristics;        // Reserved, must be 0
    DWORD   TimeDateStamp;          // Timestamp of when the resource data was created
    WORD    MajorVersion;           // Major version number
    WORD    MinorVersion;           // Minor version number
    WORD    NumberOfNamedEntries;   // Number of directory entries that follow which are identified by name
    WORD    NumberOfIdEntries;      // Number of directory entries that follow which are identified by ID
    // IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[]; // Array of entries follows this struct
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
```

**โครงสร้างของ `IMAGE_RESOURCE_DIRECTORY_ENTRY` (แต่ละ entry มีขนาด 8 bytes):**

```c
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset:31;     // Offset to a IMAGE_RESOURCE_DIR_STRING_U structure
            DWORD NameIsString:1;    // If 1, NameOffset is an offset; if 0, Name is an ID
        } DUMMYSTRUCTNAME;
        DWORD   Name;                // Integer ID of the resource/directory
        WORD    Id;                  // Integer ID of the resource/directory (for named entries, this is an offset)
    } DUMMYUNIONNAME;
    union {
        DWORD   OffsetToData;        // If DataIsDirectory is 0, this is an offset to IMAGE_RESOURCE_DATA_ENTRY
                                     // If DataIsDirectory is 1, this is an offset to another IMAGE_RESOURCE_DIRECTORY
        struct {
            DWORD   OffsetToDirectory:31; // Offset to another IMAGE_RESOURCE_DIRECTORY
            DWORD   DataIsDirectory:1;    // If 1, this entry points to another directory; if 0, to data
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
```

**การจัดโครงสร้างแบบต้นไม้ 3 ระดับ:**

ทรัพยากรใน PE file โดยทั่วไปจะถูกจัดเรียงเป็นโครงสร้างต้นไม้ 3 ระดับ:

1.  **ระดับที่ 1: ประเภท (Type) ของทรัพยากร**
    *   Root `IMAGE_RESOURCE_DIRECTORY` (ที่ชี้โดย Data Directory) จะมี `IMAGE_RESOURCE_DIRECTORY_ENTRY` หลายตัว แต่ละตัวแทนประเภทของทรัพยากร
    *   ประเภทสามารถระบุด้วย **ชื่อ** (เช่น "CURSOR", "BITMAP", "MENU") หรือด้วย **Integer ID** ที่กำหนดไว้ล่วงหน้า (Well-Known Resource Types):
        *   `RT_CURSOR` (1)
        *   `RT_BITMAP` (2)
        *   `RT_ICON` (3)
        *   `RT_MENU` (4)
        *   `RT_DIALOG` (5)
        *   `RT_STRING` (6) (String Table)
        *   `RT_FONTDIR` (7)
        *   `RT_FONT` (8)
        *   `RT_ACCELERATOR` (9)
        *   `RT_RCDATA` (10) (Raw Character Data - สำหรับข้อมูลไบนารีที่กำหนดเอง)
        *   `RT_MESSAGETABLE` (11)
        *   `RT_GROUP_CURSOR` (12)
        *   `RT_GROUP_ICON` (14)
        *   `RT_VERSION` (16) (Version Information)
        *   `RT_DLGINCLUDE` (17)
        *   `RT_PLUGPLAY` (19)
        *   `RT_VXD` (20)
        *   `RT_ANICURSOR` (21)
        *   `RT_ANIICON` (22)
        *   `RT_HTML` (23)
        *   `RT_MANIFEST` (24) (Application Manifest - เช่น สำหรับ SxS, UAC elevation)
    *   แต่ละ entry ประเภทนี้จะชี้ไปยัง `IMAGE_RESOURCE_DIRECTORY` อีกอัน (ระดับที่ 2) โดยตั้งค่า `DataIsDirectory` bit เป็น 1

2.  **ระดับที่ 2: ชื่อ/ID (Name/Identifier) ของทรัพยากร**
    *   `IMAGE_RESOURCE_DIRECTORY` ที่ชี้มาจากระดับที่ 1 จะมี `IMAGE_RESOURCE_DIRECTORY_ENTRY` หลายตัว แต่ละตัวแทนทรัพยากรเฉพาะภายใต้ประเภทนั้นๆ
    *   ทรัพยากรเฉพาะนี้สามารถระบุด้วย **ชื่อ** (เช่น ชื่อไอคอน "MAINICON") หรือด้วย **Integer ID**
    *   แต่ละ entry ชื่อ/ID นี้จะชี้ไปยัง `IMAGE_RESOURCE_DIRECTORY` อีกอัน (ระดับที่ 3) โดยตั้งค่า `DataIsDirectory` bit เป็น 1

3.  **ระดับที่ 3: ภาษา (Language) ของทรัพยากร**
    *   `IMAGE_RESOURCE_DIRECTORY` ที่ชี้มาจากระดับที่ 2 จะมี `IMAGE_RESOURCE_DIRECTORY_ENTRY` หลายตัว แต่ละตัวแทนเวอร์ชันของทรัพยากรนั้นๆ สำหรับ **ภาษาที่แตกต่างกัน**
    *   ภาษาจะถูกระบุด้วย **Language ID (LANGID)** ซึ่งเป็น WORD ที่ประกอบด้วย Primary Language ID และ Sublanguage ID (เช่น `0x0409` สำหรับ English - United States, `0x041E` สำหรับ Thai - Thailand)
    *   แต่ละ entry ภาษานี้จะชี้ไปยัง **ข้อมูลทรัพยากรจริง** โดยตั้งค่า `DataIsDirectory` bit เป็น 0 และ `OffsetToData` จะเป็น RVA ที่ชี้ไปยังโครงสร้าง `IMAGE_RESOURCE_DATA_ENTRY`

**การระบุชื่อหรือ ID ใน `IMAGE_RESOURCE_DIRECTORY_ENTRY`:**
*   ฟิลด์ `Name` (union) ใน `IMAGE_RESOURCE_DIRECTORY_ENTRY` จะถูกตีความโดยใช้บิต `NameIsString` (MSB ของ `Name`):
    *   ถ้า `NameIsString` == 1: `NameOffset` (31 บิตล่าง) จะเป็น offset (จากจุดเริ่มต้นของ resource section ทั้งหมด) ไปยังโครงสร้าง `IMAGE_RESOURCE_DIR_STRING_U` ซึ่งเก็บความยาวของชื่อ (WORD) ตามด้วยสตริงชื่อ (Unicode, ไม่ใช่ null-terminated)
    *   ถ้า `NameIsString` == 0: `Id` (16 บิตล่างของ `Name`) จะเป็น Integer ID ของประเภท, ชื่อ, หรือภาษา

## 11.2 โครงสร้าง `IMAGE_RESOURCE_DATA_ENTRY`

เมื่อเดินตามโครงสร้างต้นไม้ 3 ระดับจนถึง entry ที่ `DataIsDirectory` bit เป็น 0, ฟิลด์ `OffsetToData` จะชี้ไปยังโครงสร้าง `IMAGE_RESOURCE_DATA_ENTRY` ซึ่งให้ข้อมูลเกี่ยวกับตำแหน่งและขนาดของข้อมูลทรัพยากรดิบ (raw resource data)

**โครงสร้างของ `IMAGE_RESOURCE_DATA_ENTRY` (ขนาด 16 bytes):**

```c
typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    DWORD   OffsetToData;           // RVA of the actual resource data
    DWORD   Size;                   // Size of the resource data in bytes
    DWORD   CodePage;               // Code page used for the resource data (usually 0)
    DWORD   Reserved;               // Reserved, must be 0
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;
```

**คำอธิบายฟิลด์:**

1.  **`OffsetToData` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ที่ชี้ไปยังจุดเริ่มต้นของ **ข้อมูลทรัพยากรดิบ (raw data)** จริงๆ ในหน่วยความจำ (และโดยทั่วไปจะอยู่ใน `.rsrc` section หรือ section อื่นที่เก็บ resources)
    *   **ข้อควรระวัง:** RVA นี้เป็น offset จาก `ImageBase` ไม่ใช่ offset จากจุดเริ่มต้นของ resource section

2.  **`Size` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาด (เป็น bytes) ของข้อมูลทรัพยากรดิบนั้นๆ

3.  **`CodePage` (DWORD - 4 bytes):**
    *   **ความหมาย:** ระบุ code page ที่ใช้สำหรับข้อมูลทรัพยากรนั้น (มีประโยชน์สำหรับ text-based resources) โดยทั่วไปมักจะเป็น 0 ซึ่งหมายถึง Unicode หรือ code page เริ่มต้น
    *   **Cybersecurity Relevance:** Code page ที่ไม่ปกติอาจเป็นเทคนิค obfuscation เล็กน้อย

4.  **`Reserved` (DWORD - 4 bytes):**
    *   **ความหมาย:** สงวนไว้ และควรมีค่าเป็น 0
    *   **Cybersecurity Relevance:** ถ้าไม่เป็น 0 อาจเป็นสัญญาณของความผิดปกติ

## 11.3 ประเภททรัพยากรที่สำคัญและ Cybersecurity Relevance

1.  **`RT_STRING` (String Table):**
    *   **โครงสร้าง:** จัดเก็บเป็นกลุ่มของ 16 สตริงต่อ "bundle" แต่ละสตริงมี WORD บอกความยาว ตามด้วยสตริง Unicode (ไม่ใช่ null-terminated)
    *   **Cybersecurity Relevance:**
        *   **Information Leakage:** สตริงที่ใช้ใน UI, error messages, หรือ debug messages อาจเปิดเผยข้อมูลเกี่ยวกับโปรแกรม, C&C URLs, ชื่อไฟล์, registry keys, หรือแม้แต่ชื่อผู้พัฒนา/กลุ่มมัลแวร์
        *   **Obfuscated Strings:** มัลแวร์มักจะเข้ารหัสหรือ obfuscate สตริงสำคัญเพื่อหลีกเลี่ยงการถูกตรวจจับได้ง่าย การไม่พบสตริงที่คาดหวัง (เช่น API names ที่ใช้บ่อย) อาจบ่งชี้ถึงการ obfuscation
        *   **Localization:** สตริงในหลายภาษาอาจบ่งชี้ถึงเป้าหมายของมัลแวร์

2.  **`RT_VERSION` (Version Information):**
    *   **โครงสร้าง:** เป็นโครงสร้าง `VS_VERSIONINFO` ที่ซับซ้อน ซึ่งเก็บข้อมูลเช่น FileVersion, ProductVersion, CompanyName, ProductName, FileDescription, LegalCopyright, OriginalFilename ฯลฯ
    *   **Cybersecurity Relevance:**
        *   **False Flag/Masquerading:** มัลแวร์มักจะปลอมแปลงข้อมูล version info ให้เหมือนกับโปรแกรมที่ถูกกฎหมาย (เช่น `svchost.exe`, `explorer.exe`) หรือไฟล์ของ Microsoft เพื่อหลอกผู้ใช้และเครื่องมือวิเคราะห์
        *   **Inconsistent Information:** ข้อมูล version info ที่ไม่สอดคล้องกัน (เช่น ProductName ไม่ตรงกับ FileDescription) หรือไม่มีข้อมูลเลยในไฟล์ที่ควรจะมี (เช่น system DLL) เป็นสัญญาณที่น่าสงสัย
        *   **InternalName/OriginalFilename:** ฟิลด์เหล่านี้อาจเปิดเผยชื่อโปรเจกต์ดั้งเดิมของมัลแวร์ (ถ้าผู้สร้างไม่ได้ลบออก)

3.  **`RT_RCDATA` (Raw Custom Data) และประเภทที่กำหนดเอง:**
    *   **โครงสร้าง:** เป็นข้อมูลไบนารีใดๆ ที่ผู้พัฒนาต้องการฝังไว้
    *   **Cybersecurity Relevance (สูงมาก):**
        *   **Embedded Payloads:** มัลแวร์มักจะซ่อน PE file อื่น (เช่น DLL ที่จะ inject, executable ที่จะ drop), shellcode, scripts (PowerShell, VBScript), หรือ configuration data ที่เข้ารหัส/บีบอัด ไว้ใน `RT_RCDATA` หรือทรัพยากรประเภทที่กำหนดเอง (custom type)
        *   **Extraction:** นักวิเคราะห์มักจะต้อง dump ข้อมูลจากทรัพยากรเหล่านี้ออกมา แล้ววิเคราะห์ต่อ (เช่น decompress, decrypt, หรือ run ใน sandbox)
        *   **Uncommon Types/Names:** การใช้ Resource Type หรือ Name/ID ที่แปลกประหลาดหรือไม่เป็นมาตรฐานสำหรับ `RT_RCDATA` อาจเป็นเทคนิคซ่อนตัว
        *   **Large Resources:** ทรัพยากร `RT_RCDATA` ที่มีขนาดใหญ่ผิดปกติควรถูกตรวจสอบอย่างละเอียด

4.  **`RT_ICON`, `RT_GROUP_ICON`, `RT_CURSOR`, `RT_BITMAP`, `RT_MENU`, `RT_DIALOG`:**
    *   **โครงสร้าง:** ข้อมูลสำหรับ GUI elements
    *   **Cybersecurity Relevance:**
        *   **Social Engineering:** มัลแวร์อาจใช้ไอคอนที่เลียนแบบโปรแกรมที่น่าเชื่อถือ (เช่น ไอคอน Word document, PDF) เพื่อหลอกให้ผู้ใช้รัน
        *   **Fake UI:** มัลแวร์อาจสร้าง dialog box ปลอมๆ เพื่อขอข้อมูล (phishing) หรือแสดง error message ปลอม
        *   โดยทั่วไปส่วน GUI ไม่ค่อยเป็นเป้าหมายหลักในการซ่อนโค้ดอันตราย แต่ก็สามารถใช้ในการหลอกลวงได้

5.  **`RT_MANIFEST` (Application Manifest):**
    *   **โครงสร้าง:** เป็น XML data ที่ให้ข้อมูลกับ OS เกี่ยวกับ dependencies, UAC elevation requirements (`requestedExecutionLevel`), SxS (Side-by-Side) assembly redirection, DPI awareness ฯลฯ
    *   **Cybersecurity Relevance:**
        *   **UAC Bypass/Abuse:** มัลแวร์อาจใช้ manifest เพื่อร้องขอสิทธิ์ administrator (ทำให้เกิด UAC prompt) หรืออาจพยายามหาช่องโหว่ในกลไก manifest
        *   **DLL Hijacking (via SxS):** ในบางกรณีที่ซับซ้อน manifest อาจเกี่ยวข้องกับการทำ DLL hijacking ผ่าน SxS redirection
        *   **Missing/Malformed Manifest:** Manifest ที่หายไปหรือผิดรูปแบบในโปรแกรมที่ควรจะมี อาจทำให้โปรแกรมทำงานผิดพลาดหรือมีพฤติกรรมที่ไม่คาดคิด

## 11.4 การเข้าถึงทรัพยากรในโปรแกรม

Windows API ให้ฟังก์ชันสำหรับค้นหา, โหลด, และเข้าถึงข้อมูลทรัพยากร:
*   `FindResource` / `FindResourceEx`: ค้นหาทรัพยากรด้วย Type, Name/ID, และ Language
*   `LoadResource`: โหลดทรัพยากรที่พบเข้าสู่หน่วยความจำ และคืน HGLOBAL handle
*   `LockResource`: ได้รับ pointer ไปยังข้อมูลทรัพยากรดิบในหน่วยความจำจาก HGLOBAL handle
*   `SizeofResource`: ได้รับขนาดของทรัพยากร
*   API เฉพาะสำหรับประเภททรัพยากร เช่น `LoadString`, `LoadIcon`, `LoadBitmap`, `CreateDialog`

## 11.5 การวิเคราะห์ทรัพยากรในงาน Cybersecurity

1.  **ใช้เครื่องมือ PE Viewer/Resource Editor:**
    *   เครื่องมือเช่น Resource Hacker, PE-bear, CFF Explorer, Pestudio สามารถแสดงโครงสร้าง resource tree และ dump ข้อมูลทรัพยากรออกมาได้
    *   สามารถดู strings, icons, version info, และ preview/extract raw data ได้

2.  **ตรวจสอบประเภทและชื่อ/ID ที่น่าสงสัย:**
    *   มองหา `RT_RCDATA` หรือ custom types ที่มีข้อมูลขนาดใหญ่หรือ entropy สูง (อาจเข้ารหัส/บีบอัด)
    *   ชื่อ/ID ที่เป็นตัวเลขสุ่มๆ หรือสตริงที่ดูไม่มีความหมาย อาจเป็นที่ซ่อน payloads

3.  **Dump และวิเคราะห์ข้อมูลดิบ:**
    *   หากพบข้อมูลที่น่าสงสัยใน `RT_RCDATA` ให้ dump ออกมาเป็นไฟล์ แล้วใช้เครื่องมืออื่นวิเคราะห์ต่อ (เช่น `file` command, hex editor, disassembler, decompiler, sandbox)
    *   พยายาม decompress (zlib, aPLib) หรือ decrypt (AES, RC4, XOR) ข้อมูลนั้น หากมีเบาะแสว่าถูกป้องกันไว้

4.  **ตรวจสอบ Version Info และ Manifest:**
    *   ดูความสอดคล้องของ Version Info
    *   ตรวจสอบ `requestedExecutionLevel` ใน Manifest

5.  **YARA Rules:**
    *   สร้าง YARA rules เพื่อตรวจจับ patterns ที่น่าสงสัยใน resource data (เช่น header ของ PE file ที่ถูกฝัง, magic bytes ของ archive format)

## 11.6 สรุป

ส่วนทรัพยากรของ PE file เป็นมากกว่าแค่ที่เก็บไอคอนและสตริง มันเป็นโครงสร้างที่ยืดหยุ่นซึ่งโปรแกรมใช้ในการจัดเก็บข้อมูลหลากหลายประเภท และน่าเสียดายที่มัลแวร์ก็ได้เรียนรู้ที่จะใช้ประโยชน์จากความยืดหยุ่นนี้ในการซ่อน payloads, configuration, และส่วนประกอบอื่นๆ ของมัน

การทำความเข้าใจโครงสร้าง Resource Directory Table, `IMAGE_RESOURCE_DIRECTORY_ENTRY`, และ `IMAGE_RESOURCE_DATA_ENTRY` รวมถึงการรู้จักประเภททรัพยากรที่สำคัญ และวิธีที่มัลแวร์อาจใช้ประโยชน์จากมัน เป็นทักษะที่จำเป็นสำหรับนักวิเคราะห์ Cybersecurity เครื่องมือที่เหมาะสมสามารถช่วยในการสำรวจและสกัดข้อมูลจากส่วนทรัพยากรได้อย่างมีประสิทธิภาพ

ในบทต่อไป เราจะมาดูกันที่ **Base Relocations** ซึ่งเป็นกลไกที่ทำให้ PE file สามารถถูกโหลดที่ `ImageBase` ใดก็ได้ในหน่วยความจำ แม้ว่าจะมี hardcoded addresses อยู่ในโค้ดก็ตาม
