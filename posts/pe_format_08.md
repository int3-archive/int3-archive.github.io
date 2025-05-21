---
date: 2025-01-08
title: PE Format บทที่ 8 - Section Table และ Sections พื้นฐาน (.text, .data, .rdata, .bss)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: Section Table (หรือบางครั้งเรียกว่า Section Headers Array) ตารางนี้เป็นหัวใจสำคัญในการอธิบายว่าเนื้อหาจริงๆ ของโปรแกรม (โค้ด, ข้อมูล, ทรัพยากร ฯลฯ)
---

# บทที่ 8 - Section Table และ Sections พื้นฐาน (.text, .data, .rdata, .bss)

หลังจาก Optional Header สิ้นสุดลง (ณ ตำแหน่งที่ระบุโดย `SizeOfOptionalHeader` ใน COFF File Header บวกกับ offset ของ Optional Header เอง) ส่วนถัดไปใน PE file คือ **Section Table** (หรือบางครั้งเรียกว่า Section Headers Array) ตารางนี้เป็นหัวใจสำคัญในการอธิบายว่าเนื้อหาจริงๆ ของโปรแกรม (โค้ด, ข้อมูล, ทรัพยากร ฯลฯ) ถูกจัดเรียงอย่างไรทั้งในไฟล์บนดิสก์และเมื่อถูกโหลดเข้าสู่หน่วยความจำ

## 8.1 Section Table (`IMAGE_SECTION_HEADER` Array)

Section Table คืออาร์เรย์ของโครงสร้าง `IMAGE_SECTION_HEADER` โดยแต่ละ entry ในอาร์เรย์นี้จะอธิบายคุณลักษณะของ "section" หนึ่งๆ ภายใน PE file จำนวนของ entries ใน Section Table ถูกกำหนดโดยฟิลด์ `NumberOfSections` ใน `IMAGE_FILE_HEADER` (COFF File Header)

**โครงสร้างของ `IMAGE_SECTION_HEADER` (แต่ละ entry มีขนาด 40 bytes):**

```c
#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; // ชื่อของ section (ASCII, null-padded, max 8 bytes)
    union {
            DWORD   PhysicalAddress;         // ไม่ได้ใช้, ควรเป็น 0
            DWORD   VirtualSize;             // ขนาดจริงของ section ในหน่วยความจำ (bytes)
    } Misc;
    DWORD   VirtualAddress;                // RVA ของจุดเริ่มต้นของ section ในหน่วยความจำ
    DWORD   SizeOfRawData;                 // ขนาดของ section ในไฟล์บนดิสก์ (bytes, multiple of FileAlignment)
    DWORD   PointerToRawData;              // File offset ของจุดเริ่มต้นของ section ในไฟล์บนดิสก์
    DWORD   PointerToRelocations;          // File offset ของ relocation entries สำหรับ section นี้ (หรือ 0)
    DWORD   PointerToLinenumbers;          // File offset ของ line-number entries สำหรับ section นี้ (หรือ 0)
    WORD    NumberOfRelocations;           // จำนวน relocation entries
    WORD    NumberOfLinenumbers;           // จำนวน line-number entries
    DWORD   Characteristics;               // Flags ที่ระบุคุณสมบัติของ section (e.g., code, data, read, write, execute)
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

**คำอธิบายฟิลด์ที่สำคัญในแต่ละ `IMAGE_SECTION_HEADER`:**

1.  **`Name` (BYTE[8] - 8 bytes):**
    *   **ความหมาย:** ชื่อของ section เป็นสตริง ASCII ที่มีความยาวสูงสุด 8 ตัวอักษร และมักจะ null-padded (เติมด้วย `\0` หากชื่อสั้นกว่า 8 ตัวอักษร)
    *   **ชื่อมาตรฐาน (Convention):**
        *   `.text`: (หรือ `CODE`) มักใช้สำหรับเก็บโค้ดที่ประมวลผลได้ (executable code)
        *   `.data`: (หรือ `DATA`) มักใช้สำหรับเก็บข้อมูลที่กำหนดค่าเริ่มต้น (initialized global/static variables)
        *   `.rdata`: มักใช้สำหรับเก็บข้อมูลแบบอ่านอย่างเดียว (read-only initialized data) เช่น constants, strings, และมักเป็นที่อยู่ของ Import/Export tables, Debug info
        *   `.bss`: มักใช้สำหรับเก็บข้อมูลที่ไม่ได้กำหนดค่าเริ่มต้น (uninitialized global/static variables) ส่วนนี้มักไม่มีข้อมูลบนดิสก์ แต่ OS จะจองพื้นที่ในหน่วยความจำให้และ initialize เป็นศูนย์
        *   `.idata`: มักใช้สำหรับ Import Directory Table และโครงสร้างที่เกี่ยวข้อง
        *   `.edata`: มักใช้สำหรับ Export Directory Table และโครงสร้างที่เกี่ยวข้อง
        *   `.rsrc`: มักใช้สำหรับ Resource data (icons, strings, dialogs)
        *   `.reloc`: มักใช้สำหรับ Base Relocation Table
        *   `.tls`: มักใช้สำหรับ Thread Local Storage data
    *   **ชื่อที่ยาวกว่า 8 ตัวอักษร:** หากชื่อ section ยาวกว่า 8 ตัวอักษร ฟิลด์ `Name` จะเริ่มต้นด้วยเครื่องหมาย slash (`/`) ตามด้วยตัวเลข ASCII ที่แทน offset ไปยังชื่อเต็มใน string table (ถ้ามี string table ซึ่งมักพบใน object files มากกว่า executables ที่ถูก stripped)
    *   **Cybersecurity Relevance:**
        *   **Uncommon Names:** ชื่อ section ที่แปลกประหลาด, ไม่มีชื่อ (เช่น `///////`), หรือชื่อที่พยายามเลียนแบบชื่อมาตรฐานแต่มีตัวอักษรผิดเพี้ยนเล็กน้อย (typo-squatting) อาจเป็นสัญญาณของ packer, obfuscator, หรือมัลแวร์
        *   **Duplicate Names:** การมี sections ที่มีชื่อซ้ำกัน (ซึ่งไม่ควรเกิดขึ้น) อาจเป็นเทคนิคหลอกเครื่องมือวิเคราะห์
        *   **Order:** ลำดับของ sections ใน Section Table อาจไม่จำเป็นต้องตรงกับลำดับในไฟล์หรือในหน่วยความจำ แต่โดยทั่วไปมักจะเรียงกัน

2.  **`Misc.VirtualSize` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาด **จริง** ของ section เมื่อถูกโหลดเข้าสู่หน่วยความจำ (เป็น bytes) ก่อนที่จะมีการจัดเรียง (alignment) ตาม `SectionAlignment`
    *   **ความแตกต่างจาก `SizeOfRawData`:**
        *   สำหรับ `.bss` section, `VirtualSize` จะมีค่าตามที่ต้องการในหน่วยความจำ แต่ `SizeOfRawData` มักจะเป็น 0 (เพราะไม่มีข้อมูลบนดิสก์)
        *   สำหรับ sections อื่นๆ `VirtualSize` อาจเท่ากับ `SizeOfRawData` หรืออาจน้อยกว่า (ถ้า `SizeOfRawData` ถูกปัดเศษขึ้นให้เป็นผลคูณของ `FileAlignment`) หรือในบางกรณีอาจใหญ่กว่าเล็กน้อย (ไม่ค่อยพบ)
    *   **Cybersecurity Relevance:**
        *   `VirtualSize` ที่ใหญ่ผิดปกติเมื่อเทียบกับ `SizeOfRawData` (ที่ไม่ใช่ .bss) อาจเป็นสัญญาณของ packer ที่จะ unpack ข้อมูลเข้ามาในส่วนที่ "ว่าง" นั้น
        *   `VirtualSize` เป็น 0 สำหรับ section ที่มีข้อมูลบนดิสก์ (`SizeOfRawData` > 0) อาจเป็นเรื่องแปลก

3.  **`VirtualAddress` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **Relative Virtual Address (RVA)** ของไบต์แรกของ section นี้ เมื่อ image ถูกโหลดเข้าสู่หน่วยความจำ (RVA นี้จะบวกกับ `ImageBase` เพื่อให้ได้ Virtual Address จริง)
    *   **การจัดเรียง:** ค่า `VirtualAddress` ของ section แรกมักจะอยู่หลัง header ทั้งหมด และค่า `VirtualAddress` ของ section ต่อๆ ไปมักจะต่อเนื่องกันโดยมีการจัดเรียงตาม `SectionAlignment` (คือ `VirtualAddress` ของ section N+1 = `VirtualAddress` ของ section N + `VirtualSize` ของ section N (ปัดเศษขึ้นให้เป็นผลคูณของ `SectionAlignment`))
    *   **Cybersecurity Relevance:**
        *   `VirtualAddress` ที่ไม่สอดคล้องกับ `SectionAlignment` หรือมีการซ้อนทับกัน (overlapping) ของ RVA ระหว่าง sections เป็นสัญญาณของไฟล์ที่ผิดปกติหรือถูกดัดแปลงอย่างร้ายแรง
        *   Sections ที่มี `VirtualAddress` เป็น 0 (ถ้าไม่ใช่กรณีพิเศษ) หรือชี้ไปยังนอก `SizeOfImage` ก็เป็นเรื่องน่าสงสัย

4.  **`SizeOfRawData` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาด (เป็น bytes) ของข้อมูลของ section นี้ **ในไฟล์ PE บนดิสก์** ค่านี้จะต้องเป็นผลคูณของ `FileAlignment` (จาก Optional Header) หากข้อมูลจริงของ section น้อยกว่านี้ มันจะถูก padded (เติมด้วย null bytes) จนครบ `FileAlignment`
    *   **ถ้าเป็น 0:** หมายความว่า section นี้ไม่มีข้อมูลบนดิสก์ (เช่น `.bss` section)
    *   **Cybersecurity Relevance:**
        *   `SizeOfRawData` ที่ไม่เป็นผลคูณของ `FileAlignment` (ถ้า `FileAlignment` > 0) เป็นสัญญาณของไฟล์ที่ผิดพลาด
        *   `SizeOfRawData` ที่ใหญ่กว่า `VirtualSize` มากๆ (สำหรับ section ที่ไม่ใช่ `.bss`) อาจมีข้อมูล "ส่วนเกิน" บนดิสก์ที่ไม่ได้ถูก map เข้าหน่วยความจำ ซึ่งมัลแวร์อาจใช้ซ่อนข้อมูล
        *   Packers อาจบีบอัดข้อมูล section ทำให้ `SizeOfRawData` เล็กกว่า `VirtualSize` มาก (เมื่อ unpack แล้วข้อมูลจะขยายตัวในหน่วยความจำ)

5.  **`PointerToRawData` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **File Offset** (ตำแหน่งไบต์จากจุดเริ่มต้นของไฟล์) ไปยังจุดเริ่มต้นของข้อมูลดิบ (raw data) ของ section นี้ในไฟล์ PE บนดิสก์ ค่านี้จะต้องเป็นผลคูณของ `FileAlignment`
    *   **ถ้าเป็น 0 (และ `SizeOfRawData` ก็เป็น 0):** หมายความว่า section นี้ไม่มีข้อมูลบนดิสก์ (เช่น `.bss` section)
    *   **Cybersecurity Relevance:**
        *   `PointerToRawData` ที่ไม่เป็นผลคูณของ `FileAlignment` หรือชี้ไปยังตำแหน่งที่อยู่นอกไฟล์ หรือชี้ทับซ้อนกับ header หรือ section อื่น เป็นสัญญาณของไฟล์ที่เสียหายหรือถูกดัดแปลงอย่างร้ายแรง
        *   `PointerToRawData` + `SizeOfRawData` ควรจะน้อยกว่าหรือเท่ากับขนาดไฟล์ทั้งหมด
        *   มัลแวร์อาจชี้ `PointerToRawData` ของ section หนึ่งไปยังข้อมูลของ section อื่น (data sharing/reuse ที่ผิดปกติ) หรือไปยังส่วนที่เป็น header

6.  **`PointerToRelocations`, `PointerToLinenumbers`, `NumberOfRelocations`, `NumberOfLinenumbers`:**
    *   **ความหมาย:** เกี่ยวข้องกับ relocation entries และ line number information สำหรับ section นั้นๆ
    *   **ใน PE Executables สมัยใหม่:** สำหรับไฟล์ PE ที่เป็น executables (.exe, .dll) ที่ถูก stripped, ค่าเหล่านี้มักจะเป็น **ศูนย์ทั้งหมด**
        *   Relocation information จะถูกเก็บใน `.reloc` section ที่ชี้จาก Data Directory (`IMAGE_DIRECTORY_ENTRY_BASERELOC`)
        *   Line number information (สำหรับ debugging) มักจะถูกลบออก หรือเก็บในไฟล์ .PDB
    *   **ใน Object Files (.obj):** ไฟล์อ็อบเจกต์ที่ยังไม่ได้ถูกลิงก์ มักจะมีค่าในฟิลด์เหล่านี้ เพราะ linker จะใช้ข้อมูลนี้ในการรวม object files และสร้าง relocation table สุดท้าย
    *   **Cybersecurity Relevance:** หาก PE executable ที่ควรจะ stripped กลับมีค่าที่ไม่ใช่ศูนย์ในฟิลด์เหล่านี้ อาจเป็นเรื่องน่าสนใจ (คล้ายกับกรณี symbol table ใน COFF Header)

7.  **`Characteristics` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็นชุดของ bit flags ที่ระบุคุณสมบัติและการอนุญาต (permissions) ของ section นี้เมื่อถูกโหลดเข้าสู่หน่วยความจำ
    *   **ค่า Flags ที่สำคัญ (ตัวอย่าง):**
        *   `IMAGE_SCN_TYPE_NO_PAD` (0x00000008): (Obsolete) ไม่ควร pad section นี้
        *   `IMAGE_SCN_CNT_CODE` (0x00000020): Section นี้มีโค้ดที่ประมวลผลได้
        *   `IMAGE_SCN_CNT_INITIALIZED_DATA` (0x00000040): Section นี้มีข้อมูลที่กำหนดค่าเริ่มต้น
        *   `IMAGE_SCN_CNT_UNINITIALIZED_DATA` (0x00000080): Section นี้มีข้อมูลที่ไม่ได้กำหนดค่าเริ่มต้น (เช่น .bss)
        *   `IMAGE_SCN_LNK_OTHER` (0x00000100): (Reserved)
        *   `IMAGE_SCN_LNK_INFO` (0x00000200): Section นี้มี comments หรือข้อมูลอื่นๆ (สำหรับ linker, มักพบใน .obj)
        *   `IMAGE_SCN_LNK_REMOVE` (0x00000800): Section นี้จะไม่ถูกรวมใน final image (สำหรับ linker, มักพบใน .obj)
        *   `IMAGE_SCN_LNK_COMDAT` (0x00001000): Section นี้เป็น COMDAT section (สำหรับ linker)
        *   `IMAGE_SCN_GPREL` (0x00008000): Section นี้มีข้อมูลที่อ้างอิงผ่าน Global Pointer (GP) (สำหรับบางสถาปัตยกรรม)
        *   `IMAGE_SCN_MEM_PURGEABLE` (0x00020000) / `IMAGE_SCN_MEM_16BIT` (0x00020000): (Conflicting/Obsolete)
        *   `IMAGE_SCN_MEM_LOCKED` (0x00040000): (Obsolete)
        *   `IMAGE_SCN_MEM_PRELOAD` (0x00080000): (Obsolete)
        *   `IMAGE_SCN_ALIGN_1BYTES` (0x00100000) ... `IMAGE_SCN_ALIGN_8192BYTES` (0x00E00000): Alignment flags (มักไม่ใช้โดยตรง, `SectionAlignment` ใน Optional Header จะควบคุม)
        *   `IMAGE_SCN_LNK_NRELOC_OVFL` (0x01000000): Section นี้มี extended relocations
        *   `IMAGE_SCN_MEM_DISCARDABLE` (0x02000000): Section นี้สามารถถูก discard (ลบออกจากหน่วยความจำ) ได้เมื่อไม่ต้องการ (เช่น resource data บางอย่าง)
        *   `IMAGE_SCN_MEM_NOT_CACHED` (0x04000000): Section นี้ไม่ควรถูก cached โดย CPU
        *   `IMAGE_SCN_MEM_NOT_PAGED` (0x08000000): Section นี้ไม่ควรถูก paged out (ต้องอยู่ใน physical memory ตลอดเวลา, เช่น สำหรับ driver บางส่วน)
        *   `IMAGE_SCN_MEM_SHARED` (0x10000000): Section นี้สามารถถูกแชร์ระหว่าง process ที่ map image เดียวกัน (Copy-on-Write (COW) หรือ shared memory จริงๆ)
        *   `IMAGE_SCN_MEM_EXECUTE` (0x20000000): Section นี้มีสิทธิ์ในการประมวลผล (Execute permission)
        *   `IMAGE_SCN_MEM_READ` (0x40000000): Section นี้มีสิทธิ์ในการอ่าน (Read permission)
        *   `IMAGE_SCN_MEM_WRITE` (0x80000000): Section นี้มีสิทธิ์ในการเขียน (Write permission)
    *   **สาเหตุ-เหตุผล:** Windows Memory Manager ใช้ flags เหล่านี้ (โดยเฉพาะ `MEM_EXECUTE`, `MEM_READ`, `MEM_WRITE`) ในการตั้งค่า access permissions สำหรับ pages ในหน่วยความจำที่ map section นั้นๆ ซึ่งเป็นส่วนสำคัญของ memory protection (เช่น DEP)
    *   **Cybersecurity Relevance:**
        *   **Dangerous Combinations:** Section ที่มีทั้ง `MEM_EXECUTE` และ `MEM_WRITE` (Writable and Executable - W+X) เป็นสิ่งที่อันตรายมาก เพราะทำให้ง่ายต่อการ inject และรัน shellcode มัลแวร์จำนวนมากพยายามสร้างหรือใช้ W+X sections Packers มักจะ unpack โค้ดลงใน W+X section
        *   **.text section ที่ Writable:** Code section (`.text`) ไม่ควรมี `MEM_WRITE` หากมี แสดงว่ามัลแวร์อาจพยายามแก้ไขโค้ดตัวเองใน runtime (self-modifying code)
        *   **.data section ที่ Executable:** Data section ไม่ควรมี `MEM_EXECUTE` หากมี แสดงว่ามัลแวร์อาจซ่อนโค้ดไว้ใน data section
        *   **Uncommon Flags:** การใช้ flags ที่ไม่ปกติ หรือ flags ที่ขัดแย้งกัน อาจเป็นเทคนิคหลอกลวง
        *   **Missing Flags:** Section ที่มีโค้ดแต่ไม่มี `IMAGE_SCN_CNT_CODE` และ `IMAGE_SCN_MEM_EXECUTE` หรือ section ที่มีข้อมูลแต่ไม่มี flags ที่เกี่ยวข้อง ก็เป็นเรื่องน่าสงสัย

## 8.2 Sections พื้นฐาน (Common Sections)

ต่อไปนี้คือ sections พื้นฐานที่มักพบใน PE files ทั่วไป พร้อมคำอธิบายเพิ่มเติม:

1.  **`.text` (หรือ `CODE`):**
    *   **เนื้อหา:** โค้ดคำสั่ง (machine instructions) ของโปรแกรม
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_CODE`, `IMAGE_SCN_MEM_EXECUTE`, `IMAGE_SCN_MEM_READ` (ควรจะเป็น Read-Only และ Execute)
    *   **Cybersecurity Focus:** เป็นเป้าหมายหลักของการทำ disassembly และ reverse engineering มัลแวร์จะซ่อนโค้ดที่เป็นอันตรายไว้ที่นี่ (หรือใน sections อื่นที่ execute ได้)

2.  **`.data` (หรือ `DATA`):**
    *   **เนื้อหา:** Global variables และ static variables ที่มีการกำหนดค่าเริ่มต้น (initialized)
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE` (Read-Write, ไม่ควร Execute)
    *   **Cybersecurity Focus:** มัลแวร์อาจเก็บ configuration, C&C server addresses (อาจเข้ารหัส), หรือ buffer ที่ใช้เก็บข้อมูลสำคัญไว้ในส่วนนี้

3.  **`.rdata` (Read-Only Data):**
    *   **เนื้อหา:** ข้อมูลแบบอ่านอย่างเดียว เช่น literal strings, constants, jump tables, และมักจะเป็นที่อยู่ของโครงสร้างข้อมูลสำคัญ เช่น Import Directory Table (IDT), Export Directory Table (EAT), Debug Directory, และบางครั้ง Resource data (ถ้าไม่ได้อยู่ใน `.rsrc` แยก)
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ` (Read-Only, ไม่ควร Execute หรือ Write)
    *   **Cybersecurity Focus:** Strings ใน `.rdata` เป็นแหล่งข้อมูลสำคัญในการวิเคราะห์ (API names, URLs, messages) โครงสร้าง IDT/EAT ที่อยู่ในนี้ (หรือชี้มาที่นี่) ก็สำคัญมาก

4.  **`.bss` (Block Started by Symbol):**
    *   **เนื้อหา:** Global variables และ static variables ที่ **ไม่** ได้มีการกำหนดค่าเริ่มต้น (uninitialized)
    *   **File vs Memory:** ส่วนนี้มักจะมี `SizeOfRawData` เป็น 0 (หรือเล็กมาก) ในไฟล์บนดิสก์ แต่ `VirtualSize` จะมีขนาดตามที่โปรแกรมต้องการ เมื่อโหลดเข้าหน่วยความจำ OS loader จะจองพื้นที่และ initialize ทั้งหมดเป็นศูนย์
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_UNINITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE` (Read-Write, ไม่ควร Execute)
    *   **Cybersecurity Focus:** มัลแวร์อาจใช้ `.bss` section ขนาดใหญ่เพื่อจองพื้นที่สำหรับ runtime data, buffers สำหรับรับข้อมูลจาก C&C, หรือเป็นพื้นที่ทำงานชั่วคราว

5.  **`.idata` (Import Data):**
    *   **เนื้อหา:** Import Directory Table (IDT) และโครงสร้างที่เกี่ยวข้อง เช่น Import Lookup Tables (ILT), Import Name Table (INT), และ Import Address Table (IAT) เมื่อยังไม่ได้ถูก resolve โดย loader
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE` (IAT จะถูกเขียนโดย loader)
    *   **Cybersecurity Focus:** การวิเคราะห์ `.idata` (หรือส่วนที่ IDT ชี้ไป) เป็นสิ่งสำคัญที่สุดในการทำความเข้าใจว่าโปรแกรมเรียกใช้ API อะไรบ้าง

6.  **`.edata` (Export Data):**
    *   **เนื้อหา:** Export Directory Table (EDT) และโครงสร้างที่เกี่ยวข้อง เช่น Export Address Table (EAT), Export Name Pointer Table, Export Ordinal Table
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`
    *   **Cybersecurity Focus:** สำคัญสำหรับ DLLs เพื่อดูว่ามีฟังก์ชันอะไรบ้างที่ export ออกไป มัลแวร์ DLL อาจ export ฟังก์ชันอันตราย

7.  **`.rsrc` (Resource Data):**
    *   **เนื้อหา:** ทรัพยากรของโปรแกรม เช่น icons, cursors, bitmaps, strings, dialog templates, version information, manifests
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ` (มักจะ Read-Only)
    *   **Cybersecurity Focus:** มัลแวร์อาจซ่อน payloads ที่เข้ารหัส, scripts, configuration data, หรือแม้แต่ PE file อื่นๆ ไว้ใน resources Version info อาจถูกปลอมแปลง Strings ใน resource อาจมีเบาะแส

8.  **`.reloc` (Relocation Data):**
    *   **เนื้อหา:** Base Relocation Table ซึ่งมีรายการของ RVA ที่ต้องถูก patch (แก้ไข) หาก image ถูกโหลดที่ `ImageBase` อื่นที่ไม่ใช่ preferred `ImageBase`
    *   **Characteristics (ทั่วไป):** `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_DISCARDABLE` (เมื่อ relocation เสร็จแล้ว section นี้สามารถ discard ได้)
    *   **Cybersecurity Focus:** หาก PE file ถูกคอมไพล์ให้รองรับ ASLR (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` flag) จะต้องมี `.reloc` section (ยกเว้นเป็น 64-bit image ที่ไม่มี hardcoded absolute addresses เลย ซึ่งหายาก) มัลแวร์ที่ไม่ต้องการถูก relocate อาจจะไม่มี section นี้ หรือมีแต่ข้อมูลไม่ถูกต้อง

## 8.3 การจัดเรียง Section Data ในไฟล์

ข้อมูลดิบ (raw data) ของแต่ละ section จะถูกจัดเก็บในไฟล์ PE ตามลำดับที่ `PointerToRawData` ของแต่ละ section header ชี้ไป ซึ่งโดยทั่วไปแล้วจะเรียงต่อกันไป แต่ไม่จำเป็นต้องติดกันสนิท (อาจมี padding bytes ระหว่าง sections เพื่อให้สอดคล้องกับ `FileAlignment`) ลำดับของ section data ในไฟล์ไม่จำเป็นต้องตรงกับลำดับของ section headers ใน Section Table เสมอไป แต่ส่วนใหญ่มักจะตรงกัน

```
+------------------------+
|      DOS MZ Header     |
+------------------------+
|    MS-DOS Stub Prog    |
+------------------------+
|      PE Signature      |
+------------------------+
|    COFF File Header    |
+------------------------+
|     Optional Header    |
+------------------------+
|     Section Table      | <--- Array of IMAGE_SECTION_HEADER
|    - Header for .text  |
|    - Header for .data  |
|    - Header for .rsrc  |
|    - ...               |
+------------------------+ <--- End of Headers (SizeOfHeaders)
|                        |
| Raw Data of .text      | <--- Pointed by .text's PointerToRawData
| (Aligned by FileAlign) |
|                        |
+------------------------+
|                        |
| Raw Data of .data      | <--- Pointed by .data's PointerToRawData
| (Aligned by FileAlign) |
|                        |
+------------------------+
|                        |
| Raw Data of .rsrc      | <--- Pointed by .rsrc's PointerToRawData
| (Aligned by FileAlign) |
|                        |
+------------------------+
|          ...           |
+------------------------+
```

## 8.4 สรุป

Section Table เป็นโครงสร้างสำคัญที่อธิบาย "กายวิภาค" (anatomy) ของ PE file ว่าประกอบด้วยส่วน (sections) อะไรบ้าง แต่ละ section มีชื่อ, ขนาดในไฟล์, ขนาดในหน่วยความจำ, ตำแหน่งในไฟล์, ตำแหน่งในหน่วยความจำ (RVA), และคุณสมบัติ (permissions) อย่างไร Windows loader ใช้ข้อมูลนี้ในการ map sections จากไฟล์เข้าสู่ virtual address space ของ process อย่างถูกต้อง และตั้งค่า memory protection ที่เหมาะสม

สำหรับนักวิเคราะห์ Cybersecurity, Section Table และคุณสมบัติของ sections พื้นฐาน (เช่น .text, .data, .rdata, .bss, .idata, .edata, .rsrc, .reloc) เป็นแหล่งข้อมูลที่สำคัญอย่างยิ่งในการทำความเข้าใจโครงสร้างของโปรแกรม, ค้นหาส่วนที่น่าสงสัย, และระบุเทคนิคที่มัลแวร์หรือ packer อาจใช้ เช่น การใช้ชื่อ section ที่ผิดปกติ, permissions ที่อันตราย (W+X), หรือการซ่อนข้อมูลใน sections ที่ไม่คาดคิด

ในบทต่อไป เราจะเริ่มเจาะลึก Data Directories ที่สำคัญ โดยเริ่มจาก **การจัดการ Imports (Import Address Table - IAT)** ซึ่งเป็นหัวใจของการ dynamic linking ใน Windows
