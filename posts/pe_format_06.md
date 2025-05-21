---
date: 2025-01-06
title: PE Format บทที่ 6 - Optional Header - ส่วนประกอบหลักและฟิลด์มาตรฐาน
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: Optional Header ชื่อนี้อาจทำให้เข้าใจผิดได้ เพราะในความเป็นจริงแล้ว ส่วนนี้ ไม่ใช่ทางเลือก (optional) แต่เป็นส่วนที่จำเป็น (mandatory) สำหรับไฟล์ PE ที่เป็น executable image (เช่น .EXE, .DLL)
---

# บทที่ 6 - Optional Header - ส่วนประกอบหลักและฟิลด์มาตรฐาน

ถัดจาก COFF File Header คือส่วนที่เรียกว่า **Optional Header** ชื่อนี้อาจทำให้เข้าใจผิดได้ เพราะในความเป็นจริงแล้ว ส่วนนี้ **ไม่ใช่ทางเลือก (optional) แต่เป็นส่วนที่จำเป็น (mandatory)** สำหรับไฟล์ PE ที่เป็น executable image (เช่น .EXE, .DLL) มันถูกเรียกว่า "Optional" เพราะสำหรับไฟล์อ็อบเจกต์ (COFF object files) ส่วนนี้อาจไม่มีอยู่ หรือมีขนาดเล็กกว่ามาก

Optional Header เป็นโครงสร้างข้อมูลที่ใหญ่และซับซ้อนที่สุดส่วนหนึ่งใน PE Header ประกอบด้วยข้อมูลจำนวนมากที่ Windows loader จำเป็นต้องใช้ในการโหลดไฟล์เข้าสู่หน่วยความจำ, กำหนดค่าเริ่มต้นของ process, และเริ่มการทำงานของโปรแกรมได้อย่างถูกต้อง

ขนาดของ Optional Header ถูกกำหนดโดยฟิลด์ `SizeOfOptionalHeader` ใน COFF File Header ที่อยู่ก่อนหน้า:
*   สำหรับ **PE32** (32-bit executables): Optional Header มีขนาดมาตรฐาน 224 bytes และใช้โครงสร้าง `IMAGE_OPTIONAL_HEADER32`
*   สำหรับ **PE32+** (64-bit executables): Optional Header มีขนาดมาตรฐาน 240 bytes และใช้โครงสร้าง `IMAGE_OPTIONAL_HEADER64` (คำว่า PE32+ เป็นชื่อเรียกอย่างเป็นทางการสำหรับ 64-bit PE files)

ในบทนี้ เราจะเน้นไปที่ฟิลด์มาตรฐานที่พบได้ทั้งใน `IMAGE_OPTIONAL_HEADER32` และ `IMAGE_OPTIONAL_HEADER64` ซึ่งส่วนใหญ่เป็นฟิลด์ที่มาจาก COFF specification ดั้งเดิม และบางส่วนที่ Windows เพิ่มเติมเข้ามาแต่ยังคงเป็นส่วน "มาตรฐาน" ของ header

## 6.1 โครงสร้างของ Optional Header (ภาพรวม)

Optional Header สามารถแบ่งออกเป็นสามส่วนหลักๆ ตามฟังก์ชันการทำงานของฟิลด์ต่างๆ:

1.  **Standard COFF Fields:** ฟิลด์เหล่านี้เป็นส่วนหนึ่งของ COFF specification ดั้งเดิม และมีความหมายคล้ายคลึงกันใน PE format
2.  **Windows-Specific Fields:** ฟิลด์เหล่านี้ถูกเพิ่มเข้ามาโดย Microsoft เพื่อรองรับคุณสมบัติและการทำงานเฉพาะของระบบปฏิบัติการ Windows
3.  **Data Directories:** เป็นอาร์เรย์ของโครงสร้าง `IMAGE_DATA_DIRECTORY` ที่ชี้ไปยังตารางข้อมูลสำคัญต่างๆ ภายใน PE file (เราจะกล่าวถึง Data Directories โดยละเอียดในบทถัดไป)

**โครงสร้างของ `IMAGE_OPTIONAL_HEADER32` (ในภาษา C):**

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //
    WORD    Magic; // 0x010b for PE32, 0x020b for PE32+
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;                  // Total size of all code sections
    DWORD   SizeOfInitializedData;       // Total size of all initialized data sections
    DWORD   SizeOfUninitializedData;     // Total size of all uninitialized data sections (e.g., .bss)
    DWORD   AddressOfEntryPoint;         // RVA of the first instruction to execute
    DWORD   BaseOfCode;                  // RVA of the beginning of the code section
    DWORD   BaseOfData;                  // RVA of the beginning of the data section (PE32 only)

    //
    // NT additional fields. (Windows-Specific Fields)
    //
    DWORD   ImageBase;                   // Preferred RVA of the first byte of image when loaded into memory
    DWORD   SectionAlignment;            // Alignment (in bytes) of sections when loaded into memory
    DWORD   FileAlignment;               // Alignment (in bytes) of raw data of sections in the file
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;           // Reserved, must be zero
    DWORD   SizeOfImage;                 // Total size of the image in memory (must be multiple of SectionAlignment)
    DWORD   SizeOfHeaders;               // Combined size of DOS Stub, PE Header, and Section Headers (rounded up to FileAlignment)
    DWORD   CheckSum;                    // Image file checksum
    WORD    Subsystem;                   // e.g., GUI, Console, Native
    WORD    DllCharacteristics;          // Flags for DLLs (and EXEs) e.g., ASLR, DEP
    DWORD   SizeOfStackReserve;          // Amount of virtual memory to reserve for the initial thread's stack
    DWORD   SizeOfStackCommit;           // Amount of virtual memory to commit for the initial thread's stack
    DWORD   SizeOfHeapReserve;           // Amount of virtual memory to reserve for the process's default heap
    DWORD   SizeOfHeapCommit;            // Amount of virtual memory to commit for the process's default heap
    DWORD   LoaderFlags;                 // Obsolete (reserved, must be zero)
    DWORD   NumberOfRvaAndSizes;         // Number of Data Directory entries in the remainder of the Optional Header

    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // Array of Data Directories
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```
*หมายเหตุ:* โครงสร้าง `IMAGE_OPTIONAL_HEADER64` จะคล้ายกันมาก แต่ฟิลด์ `ImageBase`, `SizeOfStackReserve`, `SizeOfStackCommit`, `SizeOfHeapReserve`, `SizeOfHeapCommit` จะเป็น `ULONGLONG` (64-bit) และจะไม่มีฟิลด์ `BaseOfData` (ซึ่งทำให้ขนาดโดยรวมของ `IMAGE_OPTIONAL_HEADER64` คือ 240 bytes เทียบกับ 224 bytes ของ `IMAGE_OPTIONAL_HEADER32`)

## 6.2 Standard COFF Fields ใน Optional Header

ฟิลด์เหล่านี้เป็นส่วนแรกของ Optional Header และส่วนใหญ่มีต้นกำเนิดมาจาก COFF specification

1.  **`Magic` (WORD - 2 bytes):**
    *   **ความหมาย:** ระบุประเภทของ image ว่าเป็น PE32 หรือ PE32+
    *   **ค่า:**
        *   `0x010b`: สำหรับ **PE32** (32-bit executable)
        *   `0x020b`: สำหรับ **PE32+** (64-bit executable)
    *   **สาเหตุ-เหตุผล:** เป็นตัวกำหนดโครงสร้างที่เหลือของ Optional Header (และบางส่วนของ PE file) ที่จะแตกต่างกันระหว่าง 32-bit และ 64-bit
    *   **Cybersecurity Relevance:**
        *   ค่า `Magic` จะต้องสอดคล้องกับฟิลด์ `Machine` ใน `IMAGE_FILE_HEADER` (เช่น ถ้า `Machine` เป็น `IMAGE_FILE_MACHINE_AMD64` (x64) แล้ว `Magic` ควรเป็น `0x020b`) หากไม่สอดคล้องกัน แสดงว่าไฟล์มีปัญหาหรือถูกดัดแปลง
        *   มัลแวร์บางตัวอาจพยายามแก้ไขค่านี้เพื่อหลอกเครื่องมือวิเคราะห์ หรือทำให้ไฟล์ไม่สามารถโหลดได้บนสถาปัตยกรรมที่ไม่ถูกต้อง

2.  **`MajorLinkerVersion` (BYTE - 1 byte) และ `MinorLinkerVersion` (BYTE - 1 byte):**
    *   **ความหมาย:** ระบุเวอร์ชัน (Major.Minor) ของ linker ที่ใช้สร้างไฟล์ PE นี้
    *   **ตัวอย่าง:** `0x0E` (14) สำหรับ Major, `0x20` (32) สำหรับ Minor อาจหมายถึง linker จาก Visual Studio 2022 (MSVC 14.32)
    *   **สาเหตุ-เหตุผล:** เป็นข้อมูล metadata ที่อาจมีประโยชน์ในการดีบักหรือติดตามปัญหาที่เกี่ยวข้องกับ linker เวอร์ชันเฉพาะ
    *   **Cybersecurity Relevance:**
        *   **Fingerprinting:** สามารถใช้เป็นส่วนหนึ่งในการ fingerprint สภาพแวดล้อมการ build ของมัลแวร์ได้ แม้ว่าผู้สร้างมัลแวร์สามารถปลอมแปลงค่านี้ได้
        *   **Uncommon Linkers:** Linker version ที่เก่ามาก หรือมาจาก linker ที่ไม่ใช่ของ Microsoft อาจเป็นที่น่าสนใจ

3.  **`SizeOfCode` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาดรวม (เป็น bytes) ของทุก sections ในไฟล์ที่มี flag `IMAGE_SCN_CNT_CODE` (โค้ดที่ประมวลผลได้) ตั้งอยู่ โดยทั่วไปคือขนาดของ `.text` section (หรือ sections อื่นๆ ที่มีโค้ด)
    *   **สาเหตุ-เหตุผล:** ให้ข้อมูลสรุปเกี่ยวกับปริมาณโค้ดใน image
    *   **Cybersecurity Relevance:**
        *   ขนาดโค้ดที่ใหญ่หรือเล็กผิดปกติเมื่อเทียบกับฟังก์ชันการทำงานที่คาดหวัง อาจเป็นสัญญาณของ packer (โค้ดจริงอาจถูกบีบอัด/เข้ารหัส) หรือมัลแวร์ขนาดเล็ก
        *   ค่านี้ควรจะสอดคล้องกับผลรวมของ `VirtualSize` ของ code sections จริงๆ (แม้ว่าจะไม่จำเป็นต้องตรงเป๊ะเสมอไป ขึ้นอยู่กับ linker)

4.  **`SizeOfInitializedData` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาดรวม (เป็น bytes) ของทุก sections ในไฟล์ที่มี flag `IMAGE_SCN_CNT_INITIALIZED_DATA` ตั้งอยู่ และไม่ใช่ code section โดยทั่วไปคือขนาดของ `.data`, `.rdata` (บางส่วน), และ sections อื่นๆ ที่มีข้อมูลที่กำหนดค่าเริ่มต้น
    *   **สาเหตุ-เหตุผล:** ให้ข้อมูลสรุปเกี่ยวกับปริมาณข้อมูลที่กำหนดค่าเริ่มต้นใน image
    *   **Cybersecurity Relevance:**
        *   ขนาดข้อมูลที่ใหญ่ผิดปกติอาจบ่งชี้ถึงการฝังข้อมูลจำนวนมาก (เช่น configuration, payloads ที่ถูกเข้ารหัส)

5.  **`SizeOfUninitializedData` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาดรวม (เป็น bytes) ของทุก sections ในไฟล์ที่มี flag `IMAGE_SCN_CNT_UNINITIALIZED_DATA` ตั้งอยู่ โดยทั่วไปคือขนาดของ `.bss` section
    *   **สาเหตุ-เหตุผล:** ส่วนนี้ไม่ได้ใช้พื้นที่บนดิสก์ (หรือใช้น้อยมาก) แต่ OS loader จะจองพื้นที่ตามขนาดนี้ในหน่วยความจำและ initialize เป็นศูนย์
    *   **Cybersecurity Relevance:**
        *   มัลแวร์อาจใช้ `.bss` section ขนาดใหญ่เพื่อจองพื้นที่สำหรับ runtime data หรือ buffer ที่จะถูกเติมข้อมูลภายหลัง

6.  **`AddressOfEntryPoint` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **Relative Virtual Address (RVA)** ของไบต์แรกของโค้ดที่จะเริ่มทำงานเมื่อ image ถูกโหลดและเตรียมพร้อมเรียบร้อยแล้ว นี่คือ "จุดเริ่มต้น" ของโปรแกรม
    *   **สาเหตุ-เหตุผล:** Windows loader จำเป็นต้องรู้ว่าจะเริ่มรันโค้ดจากที่ไหน
    *   **Cybersecurity Relevance:**
        *   **Crucial for Analysis:** นี่คือจุดที่นักวิเคราะห์มัลแวร์มักจะเริ่มการวิเคราะห์โค้ด (static หรือ dynamic)
        *   **Packers/Obfuscators:** Packers มักจะเปลี่ยน `AddressOfEntryPoint` ให้ชี้ไปยังโค้ด unpacker stub ของตัวเอง โค้ด unpacker นี้จะทำการถอดรหัส/คลายการบีบอัด Original Entry Point (OEP) และโค้ดส่วนอื่นๆ แล้วจึงกระโดดไปยัง OEP เพื่อเริ่มการทำงานของโปรแกรมเดิม การค้นหา OEP เป็นขั้นตอนสำคัญในการวิเคราะห์มัลแวร์ที่ถูก pack
        *   **Anomalous Entry Point:** Entry point ที่ชี้ไปยัง section ที่ไม่ใช่ code section (เช่น .data, .rsrc) หรือชี้ไปยังนอก `SizeOfImage` หรือชี้ไปยังส่วนท้ายของ code section เป็นสัญญาณที่น่าสงสัยอย่างยิ่ง
        *   **Entry Point = 0:** สำหรับ DLLs บางประเภท (เช่น resource-only DLLs) entry point อาจเป็น 0 ซึ่งหมายความว่าไม่มีโค้ดที่จะรันเมื่อ DLL ถูกโหลด (ฟังก์ชัน `DllMain` จะไม่ถูกเรียก) แต่ถ้าเป็น EXE แล้ว entry point เป็น 0 จะไม่สามารถทำงานได้

7.  **`BaseOfCode` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ของจุดเริ่มต้นของส่วนที่เป็นโค้ด (code region) โดยทั่วไปจะชี้ไปยัง RVA ของ `.text` section แรก
    *   **สาเหตุ-เหตุผล:** เป็นข้อมูลที่อาจมีประโยชน์สำหรับ linker หรือ debugger
    *   **Cybersecurity Relevance:**
        *   ค่านี้ควรจะสอดคล้องกับ `VirtualAddress` ของ code section แรกใน Section Table
        *   หาก `AddressOfEntryPoint` อยู่ก่อน `BaseOfCode` อาจเป็นเรื่องแปลก (แม้ว่าจะมีกรณีที่ถูกต้องได้ เช่น entry point stub เล็กๆ ก่อน code section หลัก)

8.  **`BaseOfData` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ของจุดเริ่มต้นของส่วนที่เป็นข้อมูล (data region) โดยทั่วไปจะชี้ไปยัง RVA ของ `.data` section แรก
    *   **การมีอยู่:** ฟิลด์นี้มีอยู่เฉพาะใน **PE32** (32-bit) เท่านั้น **ไม่มีใน PE32+** (64-bit)
    *   **สาเหตุ-เหตุผล (ที่ไม่มีใน PE32+):** ใน 64-bit ไม่มีแนวคิด "data region" ที่แยกจากกันอย่างชัดเจนเหมือนใน 32-bit โค้ดและข้อมูลสามารถอยู่ปะปนกันได้มากขึ้น (ภายใต้การควบคุมของ section permissions)
    *   **Cybersecurity Relevance (สำหรับ PE32):**
        *   ควรสอดคล้องกับ `VirtualAddress` ของ data section แรก
        *   หาก `AddressOfEntryPoint` อยู่ใน data region (หลัง `BaseOfData`) นั่นเป็นสัญญาณอันตรายอย่างยิ่ง (อาจเป็น shellcode ที่ถูกฉีดเข้ามา)

## 6.3 สรุปส่วนฟิลด์มาตรฐาน

ฟิลด์มาตรฐานใน Optional Header ให้ข้อมูลพื้นฐานที่สำคัญเกี่ยวกับ image เช่น ประเภท (32/64-bit), เวอร์ชัน linker, ขนาดของโค้ดและข้อมูล, และที่สำคัญที่สุดคือ **AddressOfEntryPoint (RVA)** ซึ่งเป็นจุดเริ่มต้นการทำงานของโปรแกรม ฟิลด์เหล่านี้เป็นจุดตรวจสอบแรกๆ สำหรับ Windows loader และเป็นแหล่งข้อมูลสำคัญสำหรับนักวิเคราะห์ Cybersecurity ในการทำความเข้าใจลักษณะเบื้องต้นของไฟล์ PE และตรวจจับความผิดปกติที่อาจบ่งชี้ถึงมัลแวร์หรือไฟล์ที่ถูกดัดแปลง

การเข้าใจความหมายและค่าที่คาดหวังของฟิลด์เหล่านี้เป็นก้าวแรกที่สำคัญก่อนที่จะไปดูฟิลด์ Windows-Specific และ Data Directories ที่ซับซ้อนยิ่งขึ้นในบทต่อไป

ในบทถัดไป (บทที่ 7) เราจะมาดูฟิลด์ที่เหลือใน Optional Header ซึ่งเป็นฟิลด์ที่ Microsoft เพิ่มเติมเข้ามาเพื่อรองรับการทำงานเฉพาะของ Windows รวมถึง Data Directories ที่เป็นหัวใจสำคัญในการเข้าถึงโครงสร้างข้อมูลอื่นๆ ภายใน PE file
