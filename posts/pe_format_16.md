---
date: 2025-01-16
title: PE Format บทที่ 16 - การวิเคราะห์ PE File เพื่อตรวจจับมัลแวร์ (Static Analysis)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: Static Analysis คือกระบวนการตรวจสอบและวิเคราะห์ PE file (หรือไฟล์ประเภทอื่นๆ) โดยไม่ต้องรัน (execute) ไฟล์นั้น
---

# บทที่ 16 - การวิเคราะห์ PE File เพื่อตรวจจับมัลแวร์ (Static Analysis)

หลังจากที่เราได้เรียนรู้โครงสร้างโดยละเอียดของ PE format และกระบวนการทำงานของมันร่วมกับระบบปฏิบัติการแล้ว ในส่วนนี้เราจะเริ่มนำความรู้เหล่านั้นมาประยุกต์ใช้ในงาน Cybersecurity โดยเน้นไปที่การวิเคราะห์ PE file เพื่อตรวจจับและทำความเข้าใจมัลแวร์

**Static Analysis** คือกระบวนการตรวจสอบและวิเคราะห์ PE file (หรือไฟล์ประเภทอื่นๆ) **โดยไม่ต้องรัน (execute) ไฟล์นั้น** เป้าหมายคือการสกัดข้อมูลให้ได้มากที่สุดเกี่ยวกับลักษณะ, โครงสร้าง, และความเป็นไปได้ที่จะเป็นอันตรายของไฟล์นั้นๆ โดยอาศัยการตรวจสอบข้อมูลที่อยู่ในตัวไฟล์เอง เช่น PE headers, sections, imports, exports, strings, และ resources

Static analysis เป็นขั้นตอนแรกที่สำคัญและมักจะทำก่อน dynamic analysis (การรันไฟล์ในสภาพแวดล้อมควบคุม) เพราะมันปลอดภัยกว่า (ไม่เสี่ยงต่อการติดเชื้อ) และสามารถให้ข้อมูลเบื้องต้นได้อย่างรวดเร็ว

## 16.1 เป้าหมายของการทำ Static Analysis กับ PE File

*   **ระบุประเภทไฟล์และความถูกต้อง:** ยืนยันว่าเป็น PE file ที่ถูกต้องหรือไม่ (32-bit/64-bit, EXE/DLL)
*   **ค้นหา Indicators of Compromise (IOCs):** สกัดข้อมูลที่สามารถใช้ระบุไฟล์หรือกิจกรรมที่เกี่ยวข้องกับมัลแวร์ เช่น hashes, IP addresses, URLs, domain names, mutex names, registry keys, file paths
*   **ประเมินความสามารถเบื้องต้น:** จาก imports, strings, resources สามารถคาดเดาได้ว่ามัลแวร์อาจจะทำอะไรได้บ้าง (เช่น network communication, file manipulation, process injection)
*   **ตรวจจับเทคนิคการซ่อนตัว:** ระบุว่าไฟล์อาจถูก pack, obfuscate, หรือใช้เทคนิค anti-analysis อื่นๆ หรือไม่
*   **สร้าง Signature หรือ YARA Rule:** หา patterns ที่เป็นเอกลักษณ์ของไฟล์เพื่อใช้ในการตรวจจับในอนาคต
*   **ตัดสินใจว่าจะทำ Dynamic Analysis ต่อหรือไม่/อย่างไร:** ข้อมูลจาก static analysis ช่วยในการวางแผนการทำ dynamic analysis (เช่น ต้องใช้ OS version ไหน, ต้อง setup network environment อย่างไร)

## 16.2 เครื่องมือที่ใช้ในการทำ Static Analysis PE File

มีเครื่องมือหลากหลายที่ช่วยในการทำ static analysis:

1.  **PE Viewers / PE Editors:**
    *   **ตัวอย่าง:** PE-bear, CFF Explorer, Pestudio, PE Explorer, LordPE
    *   **ความสามารถ:** แสดงโครงสร้าง PE header ทั้งหมด (DOS, COFF, Optional, Data Directories, Section Table), แสดง disassembly เบื้องต้น, hexdump, string extraction, resource viewer/extractor, import/export viewer
    *   **การใช้งาน:** เป็นเครื่องมือหลักในการสำรวจโครงสร้าง PE และหาความผิดปกติ

2.  **Hex Editors:**
    *   **ตัวอย่าง:** HxD, 010 Editor (มี PE template), Hex Workshop
    *   **ความสามารถ:** ดูและแก้ไข raw bytes ของไฟล์โดยตรง
    *   **การใช้งาน:** มีประโยชน์ในการดูข้อมูลที่ PE viewer อาจจะตีความผิด หรือในการค้นหา byte patterns ที่เฉพาะเจาะจง

3.  **String Extractors:**
    *   **ตัวอย่าง:** `strings` (Linux/macOS command), Sysinternals `strings.exe` (Windows), FLOSS (FireEye Labs Obfuscated String Solver)
    *   **ความสามารถ:** ดึงลำดับของ printable characters (ASCII, Unicode) ออกจากไฟล์
    *   **การใช้งาน:** Strings มักจะให้เบาะแสสำคัญ (URLs, IPs, commands, error messages, API names ที่ถูก resolve แบบ dynamic) FLOSS สามารถช่วย decode สตริงที่ถูก obfuscate แบบง่ายๆ ได้

4.  **File Hashing Tools:**
    *   **ตัวอย่าง:** `md5sum`, `sha1sum`, `sha256sum` (Linux/macOS), `certutil -hashfile` (Windows), HashMyFiles (NirSoft)
    *   **ความสามารถ:** คำนวณ cryptographic hash (MD5, SHA1, SHA256, etc.) ของไฟล์
    *   **การใช้งาน:** Hash เป็น unique identifier ของไฟล์ ใช้ในการค้นหาข้อมูลเกี่ยวกับไฟล์ในฐานข้อมูลมัลแวร์ (เช่น VirusTotal), ใช้เป็น IOC, หรือตรวจสอบความสมบูรณ์ของไฟล์

5.  **YARA และ Signature Scanners:**
    *   **YARA:** เป็นเครื่องมือ (และภาษา) สำหรับสร้าง "rules" (คำอธิบายของ malware families หรือ patterns) เพื่อใช้ในการระบุไฟล์ที่ตรงกับ rule นั้นๆ โดยดูจาก strings, byte sequences, PE structure, etc.
    *   **Antivirus Scanners (Command-line):** บาง Antivirus มี command-line version ที่สามารถใช้ scan ไฟล์เดียวได้
    *   **การใช้งาน:** ใช้ YARA rules ที่มีอยู่หรือสร้างขึ้นเองเพื่อ scan หาไฟล์ที่น่าสงสัย หรือตรวจสอบว่าไฟล์ตรงกับ malware family ที่รู้จักหรือไม่

6.  **Entropy Analyzers:**
    *   **ตัวอย่าง:** บาง PE viewers (Pestudio), `binwalk -E`
    *   **ความสามารถ:** คำนวณ entropy (ความสุ่ม) ของข้อมูลในส่วนต่างๆ ของไฟล์
    *   **การใช้งาน:** ส่วนที่มี entropy สูง (ใกล้ 8) อาจบ่งชี้ถึงข้อมูลที่ถูกบีบอัด (compressed) หรือเข้ารหัส (encrypted) ซึ่งมักพบใน packed malware

7.  **Disassemblers (สำหรับ Static Analysis เบื้องต้น):**
    *   **ตัวอย่าง:** IDA Pro (มี Free version), Ghidra, Radare2, Cutter
    *   **ความสามารถ:** แปลง machine code ใน `.text` section (หรือส่วนอื่นที่มีโค้ด) กลับเป็น Assembly language
    *   **การใช้งาน:** แม้จะเป็น static analysis การดู disassembly ของ entry point, TLS callbacks, หรือฟังก์ชันที่น่าสงสัย สามารถให้ข้อมูลเชิงลึกได้มาก (แม้จะยังไม่รันโค้ด)

8.  **Online Sandboxes และ Malware Databases (สำหรับข้อมูลประกอบ):**
    *   **ตัวอย่าง:** VirusTotal, Hybrid Analysis, Any.Run, Joe Sandbox
    *   **การใช้งาน:** Upload hash หรือไฟล์ (ด้วยความระมัดระวัง!) เพื่อดูผลการ scan จาก AV engines ต่างๆ, ดูรายงาน dynamic analysis ที่คนอื่นเคยทำ, และดู IOCs ที่เกี่ยวข้อง

## 16.3 ขั้นตอนและจุดตรวจสอบสำคัญในการทำ Static Analysis PE File

ต่อไปนี้คือจุดตรวจสอบและข้อมูลที่ควรพิจารณาเมื่อทำ static analysis กับ PE file ที่น่าสงสัย โดยอ้างอิงจากความรู้เรื่อง PE structure ที่เราเรียนมา:

1.  **File Identification และ Basic Properties:**
    *   **File Type:** ใช้ `file` command หรือดู magic bytes ("MZ" ที่ offset 0, "PE\0\0" ที่ `e_lfanew`)
    *   **Hashes (MD5, SHA1, SHA256):** คำนวณและค้นหาบน VirusTotal หรือฐานข้อมูลอื่น
    *   **File Size:** ขนาดที่เล็กมาก (ไม่กี่ KB) หรือใหญ่มาก (หลาย MB) อาจน่าสนใจ
    *   **Compilation Timestamp (`TimeDateStamp` ใน COFF Header):**
        *   สมเหตุสมผลหรือไม่? (ไม่ใช่อนาคต หรือเก่าเกินไป)
        *   อาจถูกปลอมแปลง (timestomping)
        *   เทียบกับ timestamp ของไฟล์ในระบบ (MACE times)
    *   **Digital Signature (`IMAGE_DIRECTORY_ENTRY_SECURITY`):**
        *   มี signature หรือไม่?
        *   ถ้ามี, valid หรือไม่? (ตรวจสอบ certificate chain, signer, timestamp ของ signature)
        *   มัลแวร์อาจไม่มี signature, ใช้ signature ที่ถูกขโมย/ปลอม, หรือ signature หมดอายุ/ถูก revoke

2.  **PE Headers:**
    *   **`IMAGE_DOS_HEADER`:**
        *   `e_magic` == "MZ"?
        *   `e_lfanew`: ชี้ไปยังตำแหน่งที่ถูกต้องของ "PE\0\0" signature หรือไม่? (ไม่ควรเล็กหรือใหญ่เกินไป)
    *   **`IMAGE_FILE_HEADER` (COFF Header):**
        *   `Machine`: ตรงกับสถาปัตยกรรมที่คาดหวังหรือไม่? (x86, x64)
        *   `NumberOfSections`: สมเหตุสมผลหรือไม่? (ไม่น้อยหรือมากเกินไป)
        *   `SizeOfOptionalHeader`: ตรงกับขนาดมาตรฐานของ PE32 (224 bytes) หรือ PE32+ (240 bytes) หรือไม่?
        *   `Characteristics`: Flags ที่ตั้งไว้สอดคล้องกับประเภทไฟล์หรือไม่? (เช่น `IMAGE_FILE_EXECUTABLE_IMAGE` สำหรับ EXE, `IMAGE_FILE_DLL` สำหรับ DLL) มี flags ที่น่าสงสัย (เช่น `IMAGE_FILE_RELOCS_STRIPPED` ทั้งที่ควรมี relocation) หรือไม่?
    *   **`IMAGE_OPTIONAL_HEADER`:**
        *   `Magic`: `0x010b` (PE32) หรือ `0x020b` (PE32+)? สอดคล้องกับ `Machine` type หรือไม่?
        *   `AddressOfEntryPoint` (OEP):
            *   ชี้ไปยัง RVA ภายใน code section ที่ถูกต้องหรือไม่? (ไม่ควรอยู่นอก `SizeOfImage` หรือใน data/resource section)
            *   Entry point ที่ 0 (สำหรับ EXE) หรือค่าที่สูงมาก/ต่ำมากผิดปกติ เป็นสัญญาณของ packer หรือความผิดปกติ
        *   `ImageBase`: Preferred load address ปกติหรือไม่? (เช่น 0x400000 สำหรับ EXE, 0x10000000 สำหรับ DLL)
        *   `SectionAlignment` / `FileAlignment`: เป็นค่าที่ถูกต้องตามสเปคหรือไม่? (power of 2, อยู่ใน range ที่กำหนด) `SectionAlignment` >= `FileAlignment`?
        *   `SizeOfImage`: สอดคล้องกับผลรวมของขนาด header และ `VirtualSize` ของ sections หรือไม่? (ต้องเป็น multiple of `SectionAlignment`)
        *   `SizeOfHeaders`: ครอบคลุม header ทั้งหมด และไม่เกิน `PointerToRawData` ของ section แรกหรือไม่?
        *   `Subsystem`: (`WINDOWS_GUI`, `WINDOWS_CUI`, `NATIVE`) สอดคล้องกับลักษณะของโปรแกรมหรือไม่?
        *   `DllCharacteristics`: Flags เกี่ยวกับ security mitigations ถูกตั้งไว้อย่างเหมาะสมหรือไม่?
            *   `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (ASLR)
            *   `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (DEP)
            *   `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (CFG)
            *   มัลแวร์อาจไม่ตั้งค่าเหล่านี้เพื่อทำให้ตัวเอง exploit ง่ายขึ้น
        *   `NumberOfRvaAndSizes`: ไม่ควรเกิน 16 (ณ ปัจจุบัน)

3.  **Section Table (`IMAGE_SECTION_HEADER` Array):**
    *   **Section Names:**
        *   ชื่อมาตรฐาน (`.text`, `.data`, `.rdata`, `.bss`, `.idata`, `.edata`, `.rsrc`, `.reloc`, `.tls`)
        *   ชื่อที่ผิดปกติ, ไม่มีชื่อ, หรือชื่อที่สร้างโดย packer (เช่น "UPX0", "ASPack", ". বেশিরভাগ")
    *   **Section Sizes:**
        *   `VirtualSize` vs `SizeOfRawData`:
            *   ถ้า `VirtualSize` >> `SizeOfRawData` (ที่ไม่ใช่ `.bss`) อาจเป็น packer ที่จะ unpack ข้อมูลลงในส่วนที่ "ว่าง" นั้น
            *   ถ้า `SizeOfRawData` >> `VirtualSize` อาจมีข้อมูล "ส่วนเกิน" บนดิสก์ที่ไม่ได้ถูก map
    *   **Section Pointers:**
        *   `VirtualAddress` และ `PointerToRawData`: สอดคล้องกับ alignment, ไม่ซ้อนทับกัน, และอยู่ในช่วงที่ถูกต้องหรือไม่?
    *   **Section Characteristics (Permissions):**
        *   **W+X (Writable and Executable):** Section ที่มีทั้ง `IMAGE_SCN_MEM_WRITE` และ `IMAGE_SCN_MEM_EXECUTE` เป็นสัญญาณอันตราย (มักใช้โดย packers หรือ shellcode)
        *   `.text` section ควรเป็น Read+Execute (ไม่ควร Write)
        *   `.data` / `.bss` sections ควรเป็น Read+Write (ไม่ควร Execute)
        *   `.rdata` / `.rsrc` ควรเป็น Read-Only
        *   Permissions ที่ไม่ตรงกับเนื้อหาของ section (เช่น code section ที่ execute ไม่ได้)
    *   **Entropy ของ Sections:**
        *   Section ที่มี entropy สูง (ใกล้ 8) มักจะบรรจุข้อมูลที่ถูกบีบอัดหรือเข้ารหัส (common for packed malware) `.text` section ของ packed file มักมี entropy สูง

4.  **Data Directories (ตรวจสอบ RVA และ Size ของแต่ละ entry):**
    *   **`IMAGE_DIRECTORY_ENTRY_IMPORT` (Imports):**
        *   DLLs ที่ import มา: มี DLL ที่น่าสงสัย หรือ DLL ที่ไม่ควรมีในโปรแกรมประเภทนี้หรือไม่?
        *   Functions ที่ import มา:
            *   API ที่อันตรายหรือใช้บ่อยโดยมัลแวร์ (เช่น `CreateRemoteThread`, `WriteProcessMemory`, `SetWindowsHookEx`, `URLDownloadToFile`, `ShellExecute`, `RegSetValueEx`, crypto API)
            *   จำนวน imports ที่น้อยมาก (อาจเป็น packed หรือใช้ dynamic API resolution)
            *   Import by ordinal (พยายาม resolve เป็นชื่อถ้าทำได้)
    *   **`IMAGE_DIRECTORY_ENTRY_EXPORT` (Exports) (สำหรับ DLLs):**
        *   ชื่อฟังก์ชันที่ export: บ่งบอกถึงความสามารถอะไร? มีชื่อที่น่าสงสัยหรือไม่?
        *   `NumberOfFunctions` vs `NumberOfNames`: ถ้า `NumberOfFunctions` > `NumberOfNames` มาก แสดงว่ามี ordinal-only exports (อาจซ่อนฟังก์ชันอันตราย)
        *   Forwarded exports ที่น่าสงสัย
    *   **`IMAGE_DIRECTORY_ENTRY_RESOURCE` (Resources):**
        *   ประเภท, ชื่อ/ID, ภาษา ของทรัพยากร
        *   Version Info: ปลอมแปลงหรือไม่?
        *   `RT_RCDATA` หรือ custom types: มีข้อมูลขนาดใหญ่, entropy สูง, หรือ patterns ที่น่าสงสัย (เช่น PE header "MZ", script shebangs) หรือไม่? Dump ออกมาวิเคราะห์ต่อ
        *   Icons: เลียนแบบโปรแกรมอื่นหรือไม่?
        *   Manifest (`RT_MANIFEST`): `requestedExecutionLevel` เป็นอย่างไร?
    *   **`IMAGE_DIRECTORY_ENTRY_BASERELOC` (Relocations):**
        *   มี `.reloc` section หรือไม่? (จำเป็นสำหรับ ASLR ถ้า image ไม่ใช่ PIC)
        *   ถ้าถูก stripped ออก (flag `IMAGE_FILE_RELOCS_STRIPPED`) แต่ `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` ไม่ได้ตั้ง อาจมีปัญหาในการ relocate
    *   **`IMAGE_DIRECTORY_ENTRY_TLS` (Thread Local Storage):**
        *   มี TLS Table หรือไม่?
        *   ถ้ามี, มี TLS Callbacks หรือไม่? (RVA ของ callbacks อยู่ที่ไหน? ชี้ไป code section หรือไม่?) TLS callbacks เป็นจุดที่น่าสนใจมากสำหรับมัลแวร์
    *   **`IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG` (Load Configuration):**
        *   มีข้อมูลเกี่ยวกับ security mitigations (SafeSEH, GS, CFG) หรือไม่?
    *   **`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` (.NET Header):**
        *   ถ้ามี แสดงว่าเป็น .NET assembly ต้องใช้เครื่องมือเฉพาะ (dnSpy, ILSpy) ในการวิเคราะห์ต่อ

5.  **String Analysis:**
    *   ใช้ `strings` หรือ FLOSS ดึง strings ทั้ง ASCII และ Unicode
    *   มองหา:
        *   IP addresses, URLs, domain names
        *   File paths, registry keys
        *   Commands, API names (ที่อาจ resolve แบบ dynamic)
        *   Error messages, debug strings
        *   Usernames, passwords (ไม่ค่อยพบแบบ plaintext)
        *   Keywords ที่เกี่ยวข้องกับมัลแวร์ (เช่น "bot", "keylog", "c2", "encrypt")
    *   Strings ที่ถูก obfuscate (เช่น base64 encoded, XORed, หรือ stack strings) อาจต้องใช้เทคนิคเพิ่มเติมในการ decode

6.  **Overlay Data:**
    *   ข้อมูลที่ต่อท้าย PE image (หลัง section สุดท้าย) และไม่ได้ถูก map เข้า memory โดย loader
    *   คำนวณขนาด overlay: `FileSize - SizeOfImage` (หรือ `FileSize` - offset ของท้าย section สุดท้ายในไฟล์)
    *   Overlay อาจมี PE file อื่น, archive, script, config data ที่มัลแวร์จะอ่านเข้ามาเอง
    *   ใช้ hex editor หรือ `binwalk` ในการตรวจสอบ overlay

## 16.4 ข้อจำกัดของ Static Analysis

*   **ไม่สามารถเห็นพฤติกรรมจริง:** Static analysis บอกได้แค่ "สิ่งที่มีอยู่" ในไฟล์ แต่ไม่สามารถบอกได้ว่าโค้ดจะทำงานอย่างไรเมื่อถูกรัน หรือจะมีการเปลี่ยนแปลงอะไรใน runtime
*   **Packers และ Obfuscators:** เทคนิคเหล่านี้ถูกออกแบบมาเพื่อขัดขวาง static analysis โดยตรง โค้ดและข้อมูลส่วนใหญ่จะถูกซ่อนไว้จนกว่าจะถูก unpack/deobfuscate ใน memory ตอน runtime Static analysis ของ packed file มักจะเห็นแค่ตัว unpacker stub
*   **Dynamic API Resolution:** ถ้ามัลแวร์ resolve API ที่ต้องการใช้ใน runtime (ผ่าน `LoadLibrary`/`GetProcAddress` หรือเทคนิคอื่น) Import Table จะไม่แสดง API เหล่านั้น
*   **Self-Modifying Code:** โค้ดที่แก้ไขตัวเองใน memory จะไม่สามารถเห็นได้จาก static analysis
*   **Environment-Dependent Behavior:** มัลแวร์อาจมีพฤติกรรมแตกต่างกันไปขึ้นอยู่กับสภาพแวดล้อม (เช่น OS version, locale, การมีอยู่ของ debugger/VM) ซึ่ง static analysis บอกไม่ได้

## 16.5 สรุป

Static analysis เป็นขั้นตอนที่สำคัญและมีประโยชน์อย่างยิ่งในการวิเคราะห์ PE file เบื้องต้นเพื่อตรวจจับมัลแวร์ โดยอาศัยความรู้ความเข้าใจในโครงสร้าง PE format และการใช้เครื่องมือที่เหมาะสม นักวิเคราะห์สามารถสกัดข้อมูลที่เป็นประโยชน์มากมายเกี่ยวกับลักษณะ, ความสามารถที่อาจมี, และเทคนิคที่ไฟล์นั้นอาจใช้

แม้ว่า static analysis จะมีข้อจำกัด (โดยเฉพาะเมื่อเจอกับ packed/obfuscated malware) แต่มันก็เป็นพื้นฐานที่แข็งแกร่งสำหรับการตัดสินใจว่าจะดำเนินการวิเคราะห์ในขั้นตอนต่อไป (เช่น dynamic analysis, reverse engineering) อย่างไร และช่วยในการสร้างสมมติฐานเกี่ยวกับพฤติกรรมของไฟล์นั้นๆ ได้เป็นอย่างดี

ในบทต่อไป เราจะมาดู **เทคนิคการซ่อนตัวของมัลแวร์ใน PE Format (PE Obfuscation & Packing)** ซึ่งเป็นความท้าทายหลักของการทำ static analysis
