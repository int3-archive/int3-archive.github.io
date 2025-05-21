---
date: 2025-01-05
title: PE Format บทที่ 5 - PE Signature และ COFF File Header
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: จุดเริ่มต้นของโครงสร้างที่สำคัญกว่าสำหรับระบบปฏิบัติการ Windows สมัยใหม่ ส่วนนี้เริ่มต้นด้วย PE Signature ตามด้วย COFF File Header
---

# บทที่ 5 - PE Signature และ COFF File Header

หลังจากที่ Windows loader อ่านค่า `e_lfanew` จาก DOS Header มันจะ "กระโดด" มายังตำแหน่งที่ฟิลด์นั้นชี้ไป ซึ่งเป็นจุดเริ่มต้นของโครงสร้างที่สำคัญกว่าสำหรับระบบปฏิบัติการ Windows สมัยใหม่ ส่วนนี้เริ่มต้นด้วย **PE Signature** ตามด้วย **COFF File Header** และ **Optional Header** ทั้งสามส่วนนี้รวมกันเรียกว่า **NT Headers** (เนื่องจากถูกนำมาใช้ครั้งแรกกับ Windows NT) หรือบางครั้งก็เรียกว่า **PE Header** ในความหมายที่กว้างขึ้น

ในบทนี้ เราจะเน้นไปที่สองส่วนแรกคือ PE Signature และ COFF File Header

## 5.1 PE Signature ("PE\0\0")

*   **ตำแหน่ง:** อยู่ ณ ตำแหน่งที่ระบุโดยฟิลด์ `e_lfanew` ใน `IMAGE_DOS_HEADER`
*   **ขนาด:** 4 bytes
*   **ค่า:** เป็นลำดับของ 4 bytes คือ `0x50 0x45 0x00 0x00` ซึ่งถ้าดูในรูปแบบ ASCII จะแทนตัวอักษร "P", "E", ตามด้วย null byte สองตัว (`"PE\0\0"`)
*   **วัตถุประสงค์:**
    1.  **ยืนยันความเป็น PE File:** เป็น "magic number" หรือ "signature" ที่ชัดเจนสำหรับ Windows loader และเครื่องมือต่างๆ เพื่อยืนยันว่าไฟล์นี้เป็น PE file ที่ถูกต้อง (หลังจากที่เห็น "MZ" signature แล้ว)
    2.  **จุดเริ่มต้นของ NT Headers:** เป็นตัวแบ่งที่ชัดเจนระหว่างส่วนของ MS-DOS (DOS Header และ Stub) กับส่วนของ NT Headers ที่ Windows ใช้จริง
*   **การตรวจสอบโดย Loader:** Windows loader จะตรวจสอบว่า ณ ตำแหน่งที่ `e_lfanew` ชี้มานั้น มีค่า 4 bytes นี้อยู่จริงหรือไม่ หากไม่ตรง Loader จะถือว่าไฟล์นั้นไม่ถูกต้องและจะไม่ทำการโหลดโปรแกรม
*   **Cybersecurity Relevance:**
    *   **Tampering/Corruption:** หาก PE Signature นี้ถูกแก้ไขหรือเสียหาย ไฟล์นั้นจะไม่สามารถทำงานได้บน Windows และเครื่องมือวิเคราะห์ PE ส่วนใหญ่ก็จะระบุว่าเป็นไฟล์ที่ไม่ถูกต้อง
    *   **Obfuscation (Rare for this field):** การพยายามซ่อนหรือแก้ไข signature นี้โดยตรงเป็นเรื่องยากที่จะทำให้ไฟล์ยังทำงานได้ เพราะเป็นจุดตรวจสอบแรกๆ ของ loader อย่างไรก็ตาม มัลแวร์อาจพยายามสร้างไฟล์ที่มี "MZ" แต่ไม่มี "PE" หรือมี "PE" ที่ตำแหน่งแปลกๆ เพื่อหลอกเครื่องมือบางชนิด
    *   **ไฟล์ที่ไม่ใช่ PE แต่มี "MZ":** บางครั้งไฟล์ที่ไม่ใช่ PE (เช่น ไฟล์ ZIP ที่มี DOS stub พิเศษ) อาจมี "MZ" แต่เมื่อ loader ตาม `e_lfanew` ไปแล้วไม่พบ "PE\0\0" ก็จะรู้ว่าไม่ใช่ PE file

## 5.2 COFF File Header (`IMAGE_FILE_HEADER`)

ถัดจาก PE Signature โดยตรงคือ **COFF File Header** หรือ `IMAGE_FILE_HEADER` โครงสร้างนี้มีขนาด 20 bytes และให้ข้อมูลทั่วไปเกี่ยวกับลักษณะของไฟล์ PE นั้นๆ ชื่อ "COFF" มาจาก "Common Object File Format" ซึ่งเป็นรูปแบบไฟล์อ็อบเจกต์และไฟล์実行ที่ใช้ในระบบ Unix และ VMS มาก่อน และ PE format ก็ได้นำโครงสร้างพื้นฐานหลายอย่างมาจาก COFF

**โครงสร้างของ `IMAGE_FILE_HEADER` (ในภาษา C):**

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;                     // สถาปัตยกรรม CPU เป้าหมาย
    WORD    NumberOfSections;            // จำนวน sections ในไฟล์
    DWORD   TimeDateStamp;               // วันที่และเวลาที่ไฟล์ถูกสร้าง (link time)
    DWORD   PointerToSymbolTable;        // File offset ของ COFF symbol table (หรือ 0 ถ้าไม่มี)
    DWORD   NumberOfSymbols;             // จำนวน entries ใน symbol table
    WORD    SizeOfOptionalHeader;        // ขนาดของ Optional Header ที่ตามมา (เป็น bytes)
    WORD    Characteristics;             // Flags ระบุคุณลักษณะของไฟล์
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

**คำอธิบายฟิลด์ที่สำคัญ:**

1.  **`Machine` (WORD - 2 bytes):**
    *   **ความหมาย:** ระบุสถาปัตยกรรมของ CPU ที่ไฟล์ PE นี้ถูกคอมไพล์มาเพื่อทำงานด้วย
    *   **ค่าตัวอย่างที่พบบ่อย:**
        *   `0x014c` (`IMAGE_FILE_MACHINE_I386`): Intel 386 หรือสถาปัตยกรรม x86 32-bit ที่เข้ากันได้
        *   `0x8664` (`IMAGE_FILE_MACHINE_AMD64`): x64 (AMD64 หรือ Intel 64) สถาปัตยกรรม 64-bit
        *   `0x0200` (`IMAGE_FILE_MACHINE_IA64`): Intel Itanium (64-bit, ไม่ค่อยพบในปัจจุบัน)
        *   `0x01c4` (`IMAGE_FILE_MACHINE_ARMNT`): ARMv7 (หรือใหม่กว่า) ที่ทำงานใน Thumb-2 mode (สำหรับ Windows RT, Windows Phone, Windows on ARM)
        *   `0xaa64` (`IMAGE_FILE_MACHINE_ARM64`): ARMv8 (หรือใหม่กว่า) 64-bit
        *   `0x0000` (`IMAGE_FILE_MACHINE_UNKNOWN`): ไม่ระบุหรือใช้ได้กับทุกสถาปัตยกรรม (พบน้อยมากสำหรับ PE executables)
    *   **สาเหตุ-เหตุผล:** Windows loader ใช้ค่านี้เพื่อตรวจสอบว่าไฟล์ PE สามารถทำงานบนสถาปัตยกรรมปัจจุบันของระบบได้หรือไม่ หากไม่ตรงกัน (เช่น พยายามรันไฟล์ x64 บนระบบ x86) loader จะปฏิเสธการโหลด
    *   **Cybersecurity Relevance:**
        *   การระบุสถาปัตยกรรมเป้าหมายของมัลแวร์เป็นสิ่งสำคัญในการวิเคราะห์ (เช่น ต้องใช้ disassembler/debugger ที่ถูกต้อง)
        *   มัลแวร์บางตัวอาจมีหลายเวอร์ชันสำหรับสถาปัตยกรรมที่ต่างกัน
        *   ค่า `Machine` ที่ผิดปกติหรือไม่สอดคล้องกับส่วนอื่นๆ ของไฟล์อาจเป็นสัญญาณของความผิดพลาดหรือการดัดแปลง

2.  **`NumberOfSections` (WORD - 2 bytes):**
    *   **ความหมาย:** ระบุจำนวนของ section headers (และ sections ข้อมูลจริง) ที่มีอยู่ในไฟล์นี้ Section Table จะตามหลัง Optional Header
    *   **สาเหตุ-เหตุผล:** Loader จำเป็นต้องรู้ว่ามีกี่ sections เพื่อที่จะอ่าน Section Table และ map sections เหล่านั้นเข้าสู่หน่วยความจำ
    *   **Cybersecurity Relevance:**
        *   จำนวน sections ที่มากหรือน้อยผิดปกติอาจเป็นที่น่าสนใจ เช่น packers บางตัวอาจสร้างไฟล์ที่มี section เดียว หรือมัลแวร์บางตัวอาจเพิ่ม section พิเศษเพื่อซ่อนโค้ด/ข้อมูล
        *   ค่านี้จะต้องสอดคล้องกับจำนวน section headers ที่มีอยู่จริงใน Section Table หากไม่ตรงกันแสดงว่าไฟล์อาจเสียหายหรือถูกดัดแปลง

3.  **`TimeDateStamp` (DWORD - 4 bytes):**
    *   **ความหมาย:** เก็บค่าเวลาในรูปแบบ Unix timestamp (จำนวนวินาทีนับจาก 1 มกราคม 1970 UTC) ซึ่งระบุเวลาที่ไฟล์นี้ถูกสร้างขึ้นโดย linker
    *   **สาเหตุ-เหตุผล:** ให้ข้อมูล metadata เกี่ยวกับเวลาที่ไฟล์ถูกคอมไพล์/ลิงก์
    *   **Cybersecurity Relevance:**
        *   **Malware Campaign Analysis:** Timestamp สามารถใช้เป็นจุดข้อมูลหนึ่งในการเชื่อมโยงมัลแวร์ตัวอย่างต่างๆ เข้าด้วยกัน หรือประมาณช่วงเวลาของแคมเปญการโจมตี
        *   **Tampering/Faking:** ผู้สร้างมัลแวร์สามารถแก้ไขค่านี้ได้อย่างง่ายดาย (เรียกว่า "timestomping") เพื่อทำให้ดูเหมือนไฟล์เก่าหรือใหม่กว่าความเป็นจริง หรือเพื่อให้ตรงกับไฟล์ระบบที่ถูกกฎหมาย เพื่อหลีกเลี่ยงการตรวจจับ
        *   **Anomaly:** Timestamp ที่เป็นอนาคต หรือเก่ามากๆ (เช่น ปี 1970) อาจเป็นสัญญาณของความผิดปกติหรือการตั้งใจปลอมแปลง

4.  **`PointerToSymbolTable` (DWORD - 4 bytes) และ `NumberOfSymbols` (DWORD - 4 bytes):**
    *   **ความหมาย:**
        *   `PointerToSymbolTable`: เป็น file offset ไปยังตำแหน่งของ COFF symbol table (ถ้ามี)
        *   `NumberOfSymbols`: จำนวนสัญลักษณ์ใน symbol table
    *   **ใน PE Executables สมัยใหม่:** สำหรับไฟล์ PE ที่เป็น executables (.exe) หรือ DLLs ที่ถูก stripped (ลบข้อมูล debug ออก) ค่าเหล่านี้มักจะเป็น **ศูนย์** ข้อมูลสัญลักษณ์ (debug information) มักจะถูกเก็บแยกไว้ในไฟล์ `.PDB` (Program Database) เพื่อลดขนาดของไฟล์ PE หลัก
    *   **ใน Object Files (.obj):** ไฟล์อ็อบเจกต์ที่ยังไม่ได้ถูกลิงก์ มักจะมี COFF symbol table และค่าเหล่านี้จะไม่เป็นศูนย์
    *   **สาเหตุ-เหตุผล:** Symbol table มีข้อมูลเกี่ยวกับชื่อฟังก์ชัน, ตัวแปร, ฯลฯ ซึ่งมีประโยชน์สำหรับการดีบัก แต่ไม่จำเป็นสำหรับการทำงานปกติของโปรแกรม
    *   **Cybersecurity Relevance:**
        *   หาก PE executable ที่ควรจะ stripped กลับมี symbol table อาจเป็นเรื่องน่าสนใจ (เช่น ไฟล์ที่คอมไพล์ในโหมด debug โดยไม่ได้ตั้งใจ หรือมัลแวร์บางตัวอาจทิ้งไว้) ซึ่งจะช่วยในการ reverse engineering ได้มาก
        *   ถ้าค่าเหล่านี้ไม่เป็นศูนย์ แต่ชี้ไปยังข้อมูลที่ไม่ใช่ symbol table ที่ถูกต้อง หรือมีจำนวน symbols ที่ไม่สมเหตุสมผล อาจเป็นสัญญาณของไฟล์ที่ผิดปกติ

5.  **`SizeOfOptionalHeader` (WORD - 2 bytes):**
    *   **ความหมาย:** ระบุขนาดเป็น bytes ของ `IMAGE_OPTIONAL_HEADER` ที่จะตามมาหลัง COFF File Header นี้
    *   **ค่าปกติ:**
        *   สำหรับ PE32 (32-bit): `0x00E0` (224 bytes)
        *   สำหรับ PE32+ (64-bit): `0x00F0` (240 bytes)
    *   **สาเหตุ-เหตุผล:** Loader จำเป็นต้องรู้ขนาดของ Optional Header เพื่อที่จะอ่านได้อย่างถูกต้องและข้ามไปยัง Section Table ที่อยู่ถัดไป
    *   **Cybersecurity Relevance:**
        *   ค่าที่ไม่ตรงกับขนาดมาตรฐานสำหรับ PE32/PE32+ (ตามที่ระบุโดย `Magic` field ใน Optional Header) เป็นสัญญาณที่ชัดเจนของไฟล์ที่เสียหายหรือถูกดัดแปลงอย่างร้ายแรง
        *   มัลแวร์บางตัวอาจพยายามแก้ไขค่านี้เพื่อทำให้เครื่องมือวิเคราะห์สับสน

6.  **`Characteristics` (WORD - 2 bytes):**
    *   **ความหมาย:** เป็นชุดของ bit flags ที่ระบุคุณลักษณะต่างๆ ของไฟล์ PE
    *   **ค่า Flags ที่สำคัญ (ตัวอย่าง):**
        *   `0x0001` (`IMAGE_FILE_RELOCS_STRIPPED`): ข้อมูล Relocation ถูกลบออกจากไฟล์ (สำหรับ executables มักจะตั้งค่านี้ เพราะ relocation จะอยู่ใน `.reloc` section ที่ชี้จาก Data Directory แทน)
        *   `0x0002` (`IMAGE_FILE_EXECUTABLE_IMAGE`): ไฟล์นี้เป็นไฟล์ที่สามารถประมวลผลได้ (executable) ไม่ใช่ object file หรือ library ที่เป็นแค่ archive
        *   `0x0004` (`IMAGE_FILE_LINE_NUMS_STRIPPED`): ข้อมูล Line number ถูกลบออกจากไฟล์ (มักจะตั้งค่านี้สำหรับ release builds)
        *   `0x0008` (`IMAGE_FILE_LOCAL_SYMS_STRIPPED`): Local symbols ถูกลบออกจากไฟล์ (มักจะตั้งค่านี้สำหรับ release builds)
        *   `0x0010` (`IMAGE_FILE_AGGRESIVE_WS_TRIM`): (Obsolete) ให้ OS trim working set ของโปรแกรมอย่างจริงจัง
        *   `0x0020` (`IMAGE_FILE_LARGE_ADDRESS_AWARE`): แอปพลิเคชันสามารถจัดการ address ที่ใหญ่กว่า 2GB ได้ (สำหรับ 32-bit applications บนระบบที่รองรับ /3GB switch หรือ 64-bit Windows)
        *   `0x0080` (`IMAGE_FILE_BYTES_REVERSED_LO`): (Obsolete) Little endian byte order (default สำหรับ PE)
        *   `0x0100` (`IMAGE_FILE_32BIT_MACHINE`): เครื่องเป้าหมายเป็นเครื่อง 32-bit (ควรจะสอดคล้องกับ `Machine` field แต่ไม่เสมอไป)
        *   `0x0200` (`IMAGE_FILE_DEBUG_STRIPPED`): Debugging information ถูกลบออกจากไฟล์และเก็บแยกใน .PDB file
        *   `0x0400` (`IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP`): ถ้า image อยู่บน removable media, ให้ OS copy และรันจาก swap file
        *   `0x0800` (`IMAGE_FILE_NET_RUN_FROM_SWAP`): ถ้า image อยู่บน network, ให้ OS copy และรันจาก swap file
        *   `0x1000` (`IMAGE_FILE_SYSTEM`): ไฟล์นี้เป็น system file (เช่น driver) ไม่ใช่ user program
        *   `0x2000` (`IMAGE_FILE_DLL`): ไฟล์นี้เป็น Dynamic-Link Library (DLL)
        *   `0x4000` (`IMAGE_FILE_UP_SYSTEM_ONLY`): ไฟล์นี้ควรจะรันบน Uni-processor (UP) system เท่านั้น (ไม่ควรโหลดบน Multi-processor (MP) system)
        *   `0x8000` (`IMAGE_FILE_BYTES_REVERSED_HI`): (Obsolete) Big endian byte order
    *   **สาเหตุ-เหตุผล:** Flags เหล่านี้ให้ข้อมูลเพิ่มเติมแก่ loader และ OS เกี่ยวกับวิธีการจัดการและโหลดไฟล์นี้
    *   **Cybersecurity Relevance:**
        *   **Misleading Flags:** มัลแวร์อาจตั้งค่า flags ที่ไม่สอดคล้องกับประเภทของไฟล์ (เช่น ไฟล์ EXE ที่ไม่มี `IMAGE_FILE_EXECUTABLE_IMAGE` หรือตั้ง `IMAGE_FILE_DLL` ทั้งที่เป็น EXE) เพื่อหลอกเครื่องมือวิเคราะห์หรือแม้แต่ loader บางเวอร์ชัน
        *   **DLL vs EXE:** การตรวจสอบ flag `IMAGE_FILE_DLL` เป็นวิธีหนึ่งในการแยกว่าไฟล์เป็น DLL หรือ EXE (แม้ว่าจะมีวิธีอื่นจาก Optional Header ด้วย)
        *   **Large Address Aware:** สำหรับมัลแวร์ 32-bit การตั้งค่า `IMAGE_FILE_LARGE_ADDRESS_AWARE` อาจทำให้มันสามารถเข้าถึง memory ได้มากขึ้นบนระบบ 64-bit (ผ่าน WOW64) ซึ่งอาจมีผลต่อพฤติกรรมบางอย่าง
        *   **Uncommon Combinations:** การมี flag combinations ที่แปลกๆ หรือขัดแย้งกันเอง อาจบ่งชี้ถึงการสร้างไฟล์ด้วยเครื่องมือที่ไม่มาตรฐาน หรือการพยายามทำอะไรบางอย่างที่ผิดปกติ

## 5.3 สรุป

PE Signature ("PE\0\0") เป็นตัวยืนยันที่ชัดเจนว่าเรากำลังเข้าสู่ส่วนหัวของ PE file ที่แท้จริง ตามมาด้วย COFF File Header ซึ่งให้ข้อมูลพื้นฐานที่สำคัญเกี่ยวกับไฟล์ เช่น สถาปัตยกรรมเป้าหมาย, จำนวน sections, เวลาที่สร้าง, ขนาดของ Optional Header ที่จะตามมา, และคุณลักษณะทั่วไปของไฟล์ผ่านทาง Characteristics flags

ฟิลด์เหล่านี้มีความสำคัญอย่างยิ่งต่อ Windows loader ในการตัดสินใจว่าจะโหลดและจัดการไฟล์ PE อย่างไร และสำหรับนักวิเคราะห์ Cybersecurity ฟิลด์เหล่านี้ก็เป็นแหล่งข้อมูลเบื้องต้นที่มีคุณค่าในการทำความเข้าใจลักษณะของไฟล์ต้องสงสัย การตรวจสอบความสอดคล้องและความสมเหตุสมผลของค่าในฟิลด์เหล่านี้สามารถเปิดเผยความผิดปกติที่อาจบ่งชี้ถึงไฟล์ที่เสียหาย, ถูกดัดแปลง, หรือเป็นมัลแวร์ได้

ในบทต่อไป เราจะเจาะลึกเข้าไปในส่วนที่ซับซ้อนและสำคัญที่สุดส่วนหนึ่งของ NT Headers นั่นคือ **Optional Header** ซึ่งเต็มไปด้วยข้อมูลที่จำเป็นสำหรับการโหลด image เข้าสู่หน่วยความจำและการทำงานของโปรแกรม
