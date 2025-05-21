---
date: 2025-01-03
title: PE Format บทที่ 3 - ภาพรวมโครงสร้างหลักของ PE File
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: ภาพรวมของโครงสร้าง (layout) ของ PE file หนึ่งไฟล์ ว่าประกอบด้วยส่วนสำคัญอะไรบ้าง และส่วนเหล่านั้นจัดเรียงกันอย่างไร
---

# บทที่ 3 - ภาพรวมโครงสร้างหลักของ PE File

หลังจากที่เราได้เรียนรู้เกี่ยวกับนิยาม, ความสำคัญ, และประวัติความเป็นมาของ PE format แล้ว ในบทนี้เราจะมาดูภาพรวมของโครงสร้าง (layout) ของ PE file หนึ่งไฟล์ ว่าประกอบด้วยส่วนสำคัญอะไรบ้าง และส่วนเหล่านั้นจัดเรียงกันอย่างไร การทำความเข้าใจภาพรวมนี้จะช่วยให้การศึกษาในรายละเอียดของแต่ละส่วนในบทต่อๆ ไปง่ายยิ่งขึ้น

PE file ไม่ได้เป็นเพียงก้อนข้อมูลไบนารีที่ไม่มีแบบแผน แต่มีโครงสร้างที่ถูกกำหนดไว้อย่างชัดเจน เพื่อให้ Windows loader และเครื่องมือต่างๆ สามารถอ่านและตีความข้อมูลภายในไฟล์ได้อย่างถูกต้อง

## 3.1 โครงสร้างระดับบนสุด (High-Level View)

เมื่อเรามอง PE file จากบนลงล่าง (top-down) เราสามารถแบ่งโครงสร้างหลักๆ ออกได้ดังนี้:

```
+-----------------------------------+
|           DOS MZ Header           |  <-- ส่วนหัวสำหรับ MS-DOS (MZ Signature)
|         (e_lfanew points here) ---+
+-----------------------------------+ |
|        MS-DOS Stub Program        |  <-- โปรแกรมเล็กๆ ที่จะรันถ้าเปิดบน DOS
+-----------------------------------+ |
                                    |
+-----------------------------------+ <--- (ตำแหน่งที่ e_lfanew ชี้มา)
|            PE Signature           |  <-- "PE\0\0"
+-----------------------------------+
|          COFF File Header         |  <-- ข้อมูลทั่วไปของไฟล์ (Machine, Sections)
+-----------------------------------+
|          Optional Header          |  <-- ข้อมูลสำคัญสำหรับการโหลด (Entry Point, ImageBase, DataDirectories)
|             - Standard Fields     |
|             - Windows-Specific    |
|             - Data Directories    |
+-----------------------------------+
|           Section Table           |  <-- ตารางข้อมูลของแต่ละ Section (Array of IMAGE_SECTION_HEADER)
|     (Array of Section Headers)    |
+-----------------------------------+
|                                   |
|             Section 1             |  <-- .text (Code)
|           (e.g., .text)           |
|                                   |
+-----------------------------------+
|             Section 2             |  <-- .data (Initialized Data)
|           (e.g., .data)           |
|                                   |
+-----------------------------------+
|             Section 3             |  <-- .rdata (Read-only Data, Imports, Exports)
|          (e.g., .rdata)           |
|                                   |
+-----------------------------------+
|                ...                |
+-----------------------------------+
|             Section N             |
|                                   |
+-----------------------------------+
|       (Overlay / Other Data)      |  <-- ข้อมูลส่วนท้าย (ถ้ามี, ไม่ได้เป็นส่วนหนึ่งของ Image ใน Memory)
+-----------------------------------+
```

**คำอธิบายส่วนประกอบหลัก:**

1.  **DOS MZ Header (`IMAGE_DOS_HEADER`):**
    *   **ตำแหน่ง:** ส่วนแรกสุดของไฟล์
    *   **วัตถุประสงค์:** เพื่อความเข้ากันได้ (backward compatibility) กับ MS-DOS และเพื่อให้ระบบปฏิบัติการรุ่นเก่าหรือ loader ที่ไม่รู้จัก PE format สามารถระบุได้ว่าไฟล์นี้ไม่ใช่ format ที่ตนเองเข้าใจ
    *   **ฟิลด์สำคัญ:**
        *   `e_magic`: มีค่า "MZ" (0x5A4D) เพื่อระบุว่าเป็น MZ executable
        *   `e_lfanew`: เป็น offset (ตำแหน่ง) จากจุดเริ่มต้นของไฟล์ไปยังตำแหน่งของ PE Signature (`"PE\0\0"`) นี่คือฟิลด์ที่สำคัญที่สุดสำหรับ Windows loader ในการค้นหา PE header ที่แท้จริง

2.  **MS-DOS Stub Program:**
    *   **ตำแหน่ง:** อยู่ถัดจาก DOS MZ Header
    *   **วัตถุประสงค์:** เป็นโปรแกรมขนาดเล็ก (optional แต่ส่วนใหญ่มักจะมี) ที่จะทำงานหากไฟล์ PE นี้ถูกพยายามรันบนระบบ MS-DOS หรือระบบที่ไม่รองรับ PE format โดยทั่วไปโปรแกรมนี้จะแสดงข้อความเช่น "This program cannot be run in DOS mode."
    *   **การทำงาน:** โค้ดนี้เป็นโค้ด 16-bit ของ MS-DOS จริงๆ

3.  **PE Signature:**
    *   **ตำแหน่ง:** อยู่ที่ offset ที่ระบุโดย `e_lfanew` ใน DOS MZ Header
    *   **ค่า:** เป็นลำดับ 4 bytes คือ `"PE\0\0"` (ASCII: 0x50, 0x45, 0x00, 0x00)
    *   **วัตถุประสงค์:** เป็นตัวยืนยันว่าหลังจากส่วน DOS stub แล้ว นี่คือจุดเริ่มต้นของโครงสร้าง PE ที่แท้จริง (บางครั้งเรียกว่า NT Headers)

4.  **COFF File Header (`IMAGE_FILE_HEADER`):**
    *   **ตำแหน่ง:** อยู่ถัดจาก PE Signature
    *   **วัตถุประสงค์:** ให้ข้อมูลทั่วไปเกี่ยวกับไฟล์ PE ซึ่งส่วนใหญ่มาจาก Common Object File Format (COFF)
    *   **ฟิลด์สำคัญ:**
        *   `Machine`: ระบุสถาปัตยกรรม CPU เป้าหมาย (เช่น x86, x64, ARM)
        *   `NumberOfSections`: จำนวนของ sections ที่มีในไฟล์นี้ (เช่น .text, .data)
        *   `TimeDateStamp`: วันที่และเวลาที่ไฟล์นี้ถูกคอมไพล์/ลิงก์
        *   `PointerToSymbolTable` / `NumberOfSymbols`: (มักเป็น 0 สำหรับ executables เนื่องจากข้อมูล debug มักจะถูกแยกไปเก็บในไฟล์ .PDB)
        *   `SizeOfOptionalHeader`: ขนาดของ Optional Header ที่ตามมา
        *   `Characteristics`: Flags ที่ระบุคุณลักษณะของไฟล์ (เช่น เป็น executable, เป็น DLL, รองรับ 32-bit word)

5.  **Optional Header (`IMAGE_OPTIONAL_HEADER32` หรือ `IMAGE_OPTIONAL_HEADER64`):**
    *   **ตำแหน่ง:** อยู่ถัดจาก COFF File Header
    *   **วัตถุประสงค์:** "Optional" ในชื่อนี้อาจทำให้เข้าใจผิดได้ เพราะส่วนนี้มีความสำคัญอย่างยิ่งและจำเป็นสำหรับการโหลดไฟล์ PE ส่วนนี้มีข้อมูลที่ Windows loader ต้องใช้ในการโหลดไฟล์เข้าสู่หน่วยความจำและเตรียมพร้อมสำหรับการทำงาน
    *   **โครงสร้างย่อย:**
        *   **Standard COFF Fields:** ฟิลด์มาตรฐานที่มาจาก COFF เช่น `Magic` (ระบุว่าเป็น PE32 หรือ PE32+), `AddressOfEntryPoint` (RVA ของจุดเริ่มต้นการทำงานของโค้ด), `BaseOfCode`, `BaseOfData`
        *   **Windows-Specific Fields:** ฟิลด์ที่ Windows เพิ่มเข้ามา เช่น `ImageBase` (ตำแหน่งที่ต้องการโหลดไฟล์ใน virtual memory), `SectionAlignment`, `FileAlignment`, `SizeOfImage`, `SizeOfHeaders`, `Subsystem` (เช่น GUI, Console), `DllCharacteristics` (flags เกี่ยวกับความปลอดภัย เช่น ASLR, DEP)
        *   **Data Directories (`IMAGE_DATA_DIRECTORY` array):** อาร์เรย์ของโครงสร้างที่ชี้ไปยังตารางข้อมูล (data structures) ที่สำคัญต่างๆ ภายในไฟล์ แต่ละ entry ใน array นี้ประกอบด้วย Relative Virtual Address (RVA) และ Size ของตารางข้อมูลนั้นๆ ตัวอย่าง Data Directories ที่สำคัญ: Export Table, Import Table, Resource Table, Exception Table, Certificate Table (Security), Base Relocation Table, Debug Directory, TLS Table, Load Config Table, IAT.

6.  **Section Table (Array of `IMAGE_SECTION_HEADER`):**
    *   **ตำแหน่ง:** อยู่ถัดจาก Optional Header
    *   **วัตถุประสงค์:** เป็นอาร์เรย์ของโครงสร้าง `IMAGE_SECTION_HEADER` โดยแต่ละ entry จะอธิบาย section หนึ่งๆ ในไฟล์ PE จำนวน entry ในตารางนี้จะเท่ากับค่า `NumberOfSections` ใน COFF File Header
    *   **ข้อมูลในแต่ละ Section Header:**
        *   `Name`: ชื่อของ section (เช่น `.text`, `.data`, `.rsrc`)
        *   `VirtualSize`: ขนาดของ section เมื่อโหลดเข้าหน่วยความจำ (อาจใหญ่กว่าขนาดบนดิสก์สำหรับ .bss)
        *   `VirtualAddress`: RVA ของจุดเริ่มต้นของ section นี้ในหน่วยความจำ
        *   `SizeOfRawData`: ขนาดของ section นี้ในไฟล์บนดิสก์ (ต้องเป็นผลคูณของ `FileAlignment`)
        *   `PointerToRawData`: Offset จากจุดเริ่มต้นของไฟล์ไปยังข้อมูลดิบของ section นี้บนดิสก์
        *   `PointerToRelocations`, `PointerToLinenumbers`, `NumberOfRelocations`, `NumberOfLinenumbers`: (มักเป็น 0 สำหรับ executables)
        *   `Characteristics`: Flags ที่ระบุคุณสมบัติของ section นี้ (เช่น โค้ด, initialized data, uninitialized data, read, write, execute)

7.  **Sections (Section Data):**
    *   **ตำแหน่ง:** อยู่ถัดจาก Section Table ข้อมูลดิบ (raw data) ของแต่ละ section จะถูกจัดเรียงตามลำดับในไฟล์ (แต่ไม่จำเป็นต้องเรียงตามลำดับใน Section Table เสมอไป ตำแหน่งจริงในไฟล์ดูจาก `PointerToRawData`)
    *   **วัตถุประสงค์:** เป็นที่เก็บเนื้อหาจริงๆ ของโปรแกรม เช่น:
        *   `.text` (หรือ `CODE`): บรรจุโค้ดคำสั่ง (executable instructions) ของโปรแกรม
        *   `.data` (หรือ `DATA`): บรรจุ global variables และ static variables ที่มีการกำหนดค่าเริ่มต้น (initialized data)
        *   `.rdata`: บรรจุข้อมูลแบบอ่านอย่างเดียว (read-only data) เช่น constants, strings และมักจะเป็นที่อยู่ของ Import Table, Export Table, Debug information
        *   `.bss`: บรรจุ uninitialized data (global/static variables ที่ไม่มีค่าเริ่มต้น) ส่วนนี้มักจะมี `SizeOfRawData` เป็น 0 ในไฟล์ แต่ `VirtualSize` จะมีค่าตามที่ต้องการ และ OS loader จะจองพื้นที่ในหน่วยความจำให้และ initialize เป็นศูนย์
        *   `.rsrc`: บรรจุทรัพยากรของโปรแกรม (icons, images, strings, menus, version info)
        *   `.idata`: บรรจุ Import Directory Table และโครงสร้างที่เกี่ยวข้อง (IAT)
        *   `.edata`: บรรจุ Export Directory Table และโครงสร้างที่เกี่ยวข้อง
        *   `.reloc`: บรรจุ Base Relocation Table
        *   อื่นๆ: อาจมี sections ที่สร้างโดย compiler/linker หรือ packer เช่น `.tls` (Thread Local Storage), sections ที่มีชื่อแปลกๆ จาก packer

8.  **Overlay / Other Data (ถ้ามี):**
    *   **ตำแหน่ง:** ส่วนท้ายสุดของไฟล์ ต่อจาก section data ทั้งหมด
    *   **วัตถุประสงค์:** ข้อมูลส่วนนี้ไม่ได้ถูก map เข้าไปใน virtual address space ของ process โดย Windows loader โดยตรง อาจเป็นข้อมูลที่โปรแกรมอ่านเข้ามาเองภายหลัง, ข้อมูลสำหรับ installer, digital signature (แม้ว่า Certificate Table จะถูกชี้จาก Data Directory แต่ตัว data เองอาจอยู่ที่นี่), หรือข้อมูลที่ packer ใส่เพิ่มเข้ามา
    *   **หมายเหตุ:** ขนาดของ Overlay คือ ขนาดไฟล์ทั้งหมด ลบด้วย `SizeOfImage` (เมื่อ `SizeOfImage` ถูกปรับให้สอดคล้องกับ `FileAlignment` ที่เหมาะสม) หรือลบด้วยตำแหน่งสิ้นสุดของ section สุดท้ายในไฟล์

## 3.2 ความสัมพันธ์ระหว่าง File Layout และ Memory Layout

สิ่งสำคัญที่ต้องเข้าใจคือ PE file มี "มุมมอง" สองแบบ:

1.  **File Layout (On-Disk Layout):** การจัดเรียงข้อมูลตามที่ปรากฏในไฟล์บนดิสก์
    *   ตำแหน่งของ sections จะถูกกำหนดโดย `PointerToRawData`
    *   ขนาดของ sections บนดิสก์คือ `SizeOfRawData`
    *   การจัดเรียงข้อมูล (alignment) บนดิสก์จะถูกควบคุมโดย `FileAlignment` (จาก Optional Header) โดยทั่วไปคือ 0x200 (512 bytes) หรือ 0x1000 (4KB)

2.  **Memory Layout (In-Memory Layout):** การจัดเรียงข้อมูลเมื่อไฟล์ PE ถูกโหลดเข้าสู่ virtual address space ของ process
    *   ตำแหน่งเริ่มต้นของ image ใน memory คือ `ImageBase` (จาก Optional Header)
    *   ตำแหน่งของ sections ใน memory จะถูกกำหนดโดย `VirtualAddress` (RVA ซึ่งจะบวกกับ `ImageBase` เพื่อให้ได้ Virtual Address จริง)
    *   ขนาดของ sections ใน memory คือ `VirtualSize`
    *   การจัดเรียงข้อมูล (alignment) ใน memory จะถูกควบคุมโดย `SectionAlignment` (จาก Optional Header) โดยทั่วไปคือ 0x1000 (4KB, ขนาด page ของหน่วยความจำ) หรือค่าที่ใหญ่กว่า

**ความแตกต่างที่สำคัญ:**
*   `FileAlignment` และ `SectionAlignment` อาจไม่เท่ากัน
*   `SizeOfRawData` (บนดิสก์) และ `VirtualSize` (ในหน่วยความจำ) ของ section อาจไม่เท่ากัน (เช่น .bss section)
*   ลำดับของ sections ในไฟล์ (ตาม `PointerToRawData`) อาจไม่จำเป็นต้องตรงกับลำดับของ sections ในหน่วยความจำ (ตาม `VirtualAddress`) แต่โดยทั่วไปมักจะตรงกัน

Windows loader มีหน้าที่อ่านข้อมูลจาก File Layout (ตาม `PointerToRawData` และ `SizeOfRawData`) และ map/copy ไปยัง Memory Layout (ตาม `VirtualAddress` และ `VirtualSize`) ให้ถูกต้องตาม `ImageBase` และ `SectionAlignment`

## 3.3 การใช้ Relative Virtual Addresses (RVAs)

PE format ใช้ **Relative Virtual Addresses (RVAs)** อย่างกว้างขวางในการอ้างอิงตำแหน่งต่างๆ ภายใน image
*   **RVA คืออะไร?** RVA คือ offset (ระยะห่าง) จากตำแหน่งเริ่มต้นของ image เมื่อถูกโหลดเข้าสู่หน่วยความจำ (คือ `ImageBase`)
*   **Virtual Address (VA) = ImageBase + RVA**
*   **ทำไมต้องใช้ RVA?**
    *   **Relocatability:** ทำให้ image สามารถถูกโหลดที่ `ImageBase` ใดก็ได้ใน virtual memory หาก `ImageBase` ที่ต้องการ (preferred `ImageBase`) ถูกใช้งานไปแล้ว OS loader สามารถโหลด image ที่ address อื่นได้ และจะใช้ Base Relocation Table (ถ้ามี) เพื่อปรับปรุง (patch) hardcoded addresses ทั้งหมดในโค้ดและข้อมูลให้ถูกต้องตาม `ImageBase` ใหม่ การใช้ RVA ทำให้โครงสร้างภายใน PE file (เช่น Data Directories, Section Table) ยังคงถูกต้องแม้ `ImageBase` จะเปลี่ยนไป เพราะ RVA เป็น "relative" กับ `ImageBase` ที่ถูกโหลดจริง
    *   **ความเป็นอิสระจากตำแหน่ง:** ช่วยให้การอ้างอิงภายใน image ไม่ต้องผูกติดกับ absolute virtual address ที่อาจเปลี่ยนแปลงได้

ฟิลด์จำนวนมากใน Optional Header (เช่น `AddressOfEntryPoint`, RVA ใน Data Directories) และใน Section Table (`VirtualAddress`) ล้วนเก็บค่าเป็น RVA

## 3.4 สรุป

ในบทนี้ เราได้เห็นภาพรวมของโครงสร้าง PE file ตั้งแต่ DOS Header, PE Signature, COFF Header, Optional Header, Section Table, และตัว Sections เอง รวมถึงความแตกต่างระหว่างการจัดเรียงข้อมูลบนดิสก์และในหน่วยความจำ และความสำคัญของ RVA โครงสร้างที่เป็นระบบนี้เป็นหัวใจสำคัญที่ทำให้ Windows สามารถโหลดและรันโปรแกรมได้อย่างมีประสิทธิภาพและปลอดภัย

ในบทต่อๆ ไป เราจะเริ่มเจาะลึกลงไปในแต่ละส่วนประกอบเหล่านี้ โดยเริ่มจาก DOS Header และ MS-DOS Stub Program เพื่อทำความเข้าใจบทบาทและรายละเอียดของแต่ละฟิลด์อย่างครบถ้วน

