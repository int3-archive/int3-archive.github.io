---
date: 2025-01-07
title: PE Format บทที่ 7 - Optional Header - Windows-Specific Fields และ Data Directories
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: สำคัญอย่างยิ่งคือ Data Directories ซึ่งทำหน้าที่เป็น "สารบัญ" ชี้ไปยังโครงสร้างข้อมูลที่สำคัญต่างๆ ภายใน PE file
---

# บทที่ 7 - Optional Header - Windows-Specific Fields และ Data Directories

ในบทที่แล้ว เราได้ทำความเข้าใจเกี่ยวกับส่วน Standard COFF Fields ของ Optional Header ไปแล้ว ในบทนี้ เราจะมาศึกษาฟิลด์ที่เหลือ ซึ่งเป็นฟิลด์ที่ Microsoft เพิ่มเติมเข้ามาเพื่อรองรับการทำงานเฉพาะของระบบปฏิบัติการ Windows (Windows-Specific Fields) และส่วนที่สำคัญอย่างยิ่งคือ **Data Directories** ซึ่งทำหน้าที่เป็น "สารบัญ" ชี้ไปยังโครงสร้างข้อมูลที่สำคัญต่างๆ ภายใน PE file

## 7.1 Windows-Specific Fields ใน Optional Header

ฟิลด์เหล่านี้อยู่ต่อจาก Standard COFF Fields และให้ข้อมูลที่ Windows loader และระบบปฏิบัติการใช้ในการจัดการ image ในหน่วยความจำ, กำหนดสภาพแวดล้อมของ process, และบังคับใช้นโยบายความปลอดภัย

1.  **`ImageBase` (DWORD สำหรับ PE32, ULONGLONG สำหรับ PE32+):**
    *   **ความหมาย:** ตำแหน่ง Virtual Address (VA) ที่ **ต้องการ (preferred)** โหลด image นี้เข้าไปในหน่วยความจำ ค่านี้จะต้องเป็นผลคูณของ 64KB (0x10000)
    *   **ค่าตัวอย่าง:**
        *   `0x00400000` สำหรับ executables (EXE) ส่วนใหญ่
        *   `0x10000000` สำหรับ DLLs ส่วนใหญ่
    *   **Relocation:** หากตำแหน่ง `ImageBase` ที่ต้องการนี้ถูกใช้งานไปแล้ว (เช่น มี DLL อื่นโหลดอยู่ที่นั่นแล้ว) Windows loader จะต้องทำการ **relocate** image นี้ไปยัง `ImageBase` อื่นที่ว่างอยู่ และจะใช้ข้อมูลจาก Base Relocation Table (ถ้ามี) เพื่อแก้ไข (patch) hardcoded addresses ทั้งหมดในโค้ดและข้อมูลให้ถูกต้องตาม `ImageBase` ใหม่ที่โหลดจริง
    *   **สาเหตุ-เหตุผล:** การมี preferred `ImageBase` ช่วยลดโอกาสที่ต้องทำ relocation ซึ่งเป็นการประหยัดเวลาในการโหลด (ถ้า `ImageBase` ไม่ชนกัน)
    *   **Cybersecurity Relevance:**
        *   `ImageBase` ที่แปลกประหลาด (เช่น 0 หรือค่าที่ต่ำมาก) อาจเป็นสัญญาณของ packer หรือมัลแวร์ที่พยายามทำอะไรบางอย่างที่ไม่ปกติ
        *   การวิเคราะห์มัลแวร์ที่ถูก relocate อาจซับซ้อนขึ้นเล็กน้อย เพราะ VA ใน disassembler/debugger จะไม่ตรงกับ RVA + preferred `ImageBase` เดิม
        *   ASLR (Address Space Layout Randomization) จะทำให้ `ImageBase` ที่โหลดจริงถูกสุ่ม (ถ้า DLL/EXE รองรับ `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`) ซึ่งทำให้การโจมตีแบบ return-to-libc หรือ ROP ยากขึ้น

2.  **`SectionAlignment` (DWORD - 4 bytes):**
    *   **ความหมาย:** การจัดเรียง (alignment) ของ sections เมื่อถูกโหลดเข้าสู่หน่วยความจำ ขนาดของแต่ละ section ในหน่วยความจำ (`VirtualSize`) จะต้องเป็นผลคูณของค่านี้
    *   **ค่าปกติ:** โดยทั่วไปคือขนาดของ page ในหน่วยความจำของสถาปัตยกรรมนั้นๆ เช่น `0x1000` (4KB) สำหรับ x86/x64, หรืออาจจะใหญ่กว่าสำหรับสถาปัตยกรรมอื่นหรือกรณีพิเศษ
    *   **สาเหตุ-เหตุผล:** การจัดเรียง sections ให้ตรงกับ page boundaries ช่วยให้ OS สามารถตั้งค่า memory protection (read/write/execute) สำหรับแต่ละ section ได้อย่างมีประสิทธิภาพผ่านทาง page table
    *   **Cybersecurity Relevance:**
        *   `SectionAlignment` ที่เล็กกว่า page size (เช่น `0x200`) หรือค่าที่แปลกประหลาด อาจเป็นเทคนิคของ packer หรือมัลแวร์เพื่อทำให้การวิเคราะห์ยากขึ้น หรือเพื่อหลบเลี่ยงเครื่องมือบางชนิด (แม้ว่า loader สมัยใหม่อาจจะบังคับให้เป็น page size อยู่ดี)
        *   ค่านี้ต้องมีค่ามากกว่าหรือเท่ากับ `FileAlignment`

3.  **`FileAlignment` (DWORD - 4 bytes):**
    *   **ความหมาย:** การจัดเรียง (alignment) ของข้อมูลดิบ (raw data) ของ sections ภายในไฟล์ PE บนดิสก์ ขนาดของแต่ละ section บนดิสก์ (`SizeOfRawData`) จะต้องเป็นผลคูณของค่านี้
    *   **ค่าปกติ:** โดยทั่วไปคือ `0x200` (512 bytes) ซึ่งเป็นขนาด sector ของดิสก์แบบเก่า หรืออาจเป็น `0x1000` (4KB) เพื่อให้สอดคล้องกับ `SectionAlignment` และลดความซับซ้อนในการ map ไฟล์
    *   **ข้อจำกัด:** ต้องเป็นค่ายกกำลังของ 2 (power of 2) และอยู่ระหว่าง 512 (0x200) ถึง 64KB (0x10000). ถ้า `SectionAlignment` น้อยกว่า page size ของสถาปัตยกรรม, `FileAlignment` จะต้องเท่ากับ `SectionAlignment`
    *   **สาเหตุ-เหตุผล:** เพื่อประสิทธิภาพในการอ่านไฟล์จากดิสก์ และถ้า `FileAlignment` ตรงกับ `SectionAlignment` จะทำให้การ map section จากไฟล์ไปยังหน่วยความจำทำได้ง่ายขึ้น (ไม่ต้อง copy ข้อมูลมาก)
    *   **Cybersecurity Relevance:**
        *   `FileAlignment` ที่ไม่ตรงตามข้อกำหนด (เช่น ไม่ใช่ power of 2 หรืออยู่นอกช่วงที่กำหนด) เป็นสัญญาณของไฟล์ที่ผิดปกติอย่างมาก
        *   Packers บางตัวอาจใช้ `FileAlignment` ที่เล็กมาก (เช่น 1 byte, ซึ่งไม่ควรจะถูกต้องตามสเปค แต่บาง loader อาจจะยอมรับ) เพื่อบีบอัดขนาดไฟล์บนดิสก์ให้มากที่สุด โดยข้อมูล section จะติดกันหมด ทำให้การแยกแยะ sections จาก hexdump ยากขึ้น

4.  **`MajorOperatingSystemVersion` (WORD - 2 bytes) และ `MinorOperatingSystemVersion` (WORD - 2 bytes):**
    *   **ความหมาย:** ระบุเวอร์ชัน (Major.Minor) **ขั้นต่ำ** ของระบบปฏิบัติการ Windows ที่ image นี้ต้องการเพื่อทำงาน
    *   **ค่าตัวอย่าง:** `4.0` (Windows NT 4.0), `5.1` (Windows XP), `6.1` (Windows 7), `10.0` (Windows 10/11)
    *   **สาเหตุ-เหตุผล:** Linker จะตั้งค่านี้ตาม target OS ที่ระบุตอน build OS loader อาจใช้ค่านี้ (แต่ไม่เสมอไป) ในการตัดสินใจว่า image เข้ากันได้กับ OS ปัจจุบันหรือไม่
    *   **Cybersecurity Relevance:**
        *   มัลแวร์อาจตั้งค่านี้ให้ต่ำมากเพื่อพยายามให้ทำงานได้บน OS เก่าๆ หรือตั้งค่าสูงเพื่อเป้าหมาย OS ที่เฉพาะเจาะจง
        *   ค่านี้สามารถถูกปลอมแปลงได้ง่าย

5.  **`MajorImageVersion` (WORD - 2 bytes) และ `MinorImageVersion` (WORD - 2 bytes):**
    *   **ความหมาย:** เวอร์ชัน (Major.Minor) ของ image เอง ซึ่งผู้พัฒนาสามารถกำหนดได้
    *   **สาเหตุ-เหตุผล:** สำหรับการควบคุมเวอร์ชันของโปรแกรม/DLL
    *   **Cybersecurity Relevance:** โดยทั่วไปไม่ค่อยมีนัยยะสำคัญทาง security มากนัก นอกจากจะใช้เป็นส่วนหนึ่งของข้อมูลประกอบการวิเคราะห์

6.  **`MajorSubsystemVersion` (WORD - 2 bytes) และ `MinorSubsystemVersion` (WORD - 2 bytes):**
    *   **ความหมาย:** ระบุเวอร์ชัน (Major.Minor) **ขั้นต่ำ** ของ subsystem (เช่น GUI, Console) ที่ image นี้ต้องการ
    *   **ค่าตัวอย่าง:** เหมือนกับ OS version (เช่น `5.1` สำหรับ XP-level console/GUI features)
    *   **สาเหตุ-เหตุผล:** คล้ายกับ OS version แต่เจาะจงไปที่ subsystem ที่ใช้งาน
    *   **Cybersecurity Relevance:** คล้ายกับ OS version

7.  **`Win32VersionValue` (DWORD - 4 bytes):**
    *   **ความหมาย:** สงวนไว้ (reserved) และ **ต้องเป็นศูนย์**
    *   **Cybersecurity Relevance:** ถ้าค่านี้ไม่เป็นศูนย์ แสดงว่าไฟล์น่าจะผิดปกติหรือถูกดัดแปลง

8.  **`SizeOfImage` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาด **ทั้งหมด** ของ image เมื่อถูกโหลดเข้าสู่หน่วยความจำ (รวมทุก headers และ sections) ค่านี้จะต้องเป็นผลคูณของ `SectionAlignment`
    *   **การคำนวณ (โดยประมาณ):** `ImageBase` + RVA ของ section สุดท้าย + `VirtualSize` ของ section สุดท้าย (ปรับขึ้นให้เป็นผลคูณของ `SectionAlignment`) - `ImageBase`
    *   **สาเหตุ-เหตุผล:** Windows loader ใช้ค่านี้ในการจองพื้นที่ virtual address space สำหรับ image ทั้งหมด
    *   **Cybersecurity Relevance:**
        *   `SizeOfImage` ที่เล็กกว่าผลรวมของขนาด header และ `VirtualSize` ของ sections ทั้งหมด หรือค่าที่ไม่เป็นผลคูณของ `SectionAlignment` เป็นสัญญาณของไฟล์ที่เสียหายหรือถูกดัดแปลง
        *   Packers อาจตั้งค่า `SizeOfImage` ให้ใหญ่กว่าความเป็นจริงเพื่อจองพื้นที่สำหรับโค้ด/ข้อมูลที่ถูก unpack ทีหลัง หรืออาจตั้งให้เล็กกว่าความเป็นจริงแล้วทำการ map memory เพิ่มเติมเองใน runtime

9.  **`SizeOfHeaders` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาดรวมของทุกส่วนที่เป็น header ในไฟล์ PE บนดิสก์ ซึ่งรวมถึง DOS Header (`IMAGE_DOS_HEADER`), MS-DOS Stub Program, PE Signature, COFF File Header (`IMAGE_FILE_HEADER`), Optional Header (`IMAGE_OPTIONAL_HEADER`), และ Section Table (array of `IMAGE_SECTION_HEADER`) ขนาดนี้จะถูกปัดเศษขึ้นให้เป็นผลคูณของ `FileAlignment`
    *   **สาเหตุ-เหตุผล:** Loader ใช้ค่านี้ในการระบุว่าส่วนที่เป็น header สิ้นสุดที่ใด และส่วนที่เป็น raw data ของ section แรกเริ่มต้นที่ใด (แม้ว่า `PointerToRawData` ของ section แรกจะให้ข้อมูลที่แม่นยำกว่า)
    *   **Cybersecurity Relevance:**
        *   `SizeOfHeaders` ที่ไม่สมเหตุสมผล (เช่น เล็กเกินไปจนไม่สามารถครอบคลุม header ทั้งหมดได้ หรือใหญ่เกินไปจนกินเข้าไปในส่วนของ section แรก) เป็นสัญญาณของไฟล์ที่ผิดปกติ
        *   มัลแวร์บางตัวอาจพยายามซ่อนโค้ดหรือข้อมูลใน "ช่องว่าง" (gap) ระหว่าง `SizeOfHeaders` กับ `PointerToRawData` ของ section แรก (ถ้ามีช่องว่างนั้น)

10. **`CheckSum` (DWORD - 4 bytes):**
    *   **ความหมาย:** Checksum ของ image file (ยกเว้นฟิลด์ CheckSum นี้เอง) อัลกอริทึมที่ใช้คำนวณ checksum ถูกระบุใน PE specification
    *   **การใช้งาน:**
        *   สำหรับ kernel-mode drivers และ DLLs สำคัญบางตัวของระบบ OS loader จะตรวจสอบ checksum นี้ตอนโหลด หากไม่ตรงกัน ไฟล์จะไม่ถูกโหลด (เพื่อความเสถียรและความปลอดภัยของระบบ)
        *   สำหรับ user-mode EXEs และ DLLs ทั่วไป OS loader มักจะ **ไม่** ตรวจสอบ checksum นี้ (ค่าสามารถเป็น 0 ได้)
    *   **สาเหตุ-เหตุผล:** เพื่อตรวจสอบความสมบูรณ์ของไฟล์ (integrity check) โดยเฉพาะไฟล์ที่สำคัญต่อระบบ
    *   **Cybersecurity Relevance:**
        *   ถ้าเป็น driver หรือ system DLL แล้ว checksum ไม่ถูกต้อง (หรือเป็น 0 ทั้งที่ควรจะมี) แสดงว่าไฟล์อาจถูกดัดแปลง
        *   มัลแวร์ที่เป็น user-mode EXE/DLL มักจะมี checksum เป็น 0 หรือถ้ามีก็อาจจะไม่ถูกต้อง เพราะไม่มีผลต่อการโหลด

11. **`Subsystem` (WORD - 2 bytes):**
    *   **ความหมาย:** ระบุประเภทของ subsystem ที่ UI (User Interface) ของโปรแกรมนี้ต้องการ
    *   **ค่าที่พบบ่อย:**
        *   `IMAGE_SUBSYSTEM_UNKNOWN` (0): ไม่ทราบ subsystem
        *   `IMAGE_SUBSYSTEM_NATIVE` (1): ไม่ต้องการ subsystem (เช่น kernel-mode drivers, native services) ไฟล์เหล่านี้ไม่สามารถรันโดยตรงจาก user mode
        *   `IMAGE_SUBSYSTEM_WINDOWS_GUI` (2): โปรแกรมทำงานใน Windows GUI subsystem (ต้องมี `USER32.DLL`, `GDI32.DLL`)
        *   `IMAGE_SUBSYSTEM_WINDOWS_CUI` (3): โปรแกรมทำงานใน Windows Console (Character User Interface) subsystem (ต้องมี `KERNEL32.DLL` สำหรับ console API)
        *   `IMAGE_SUBSYSTEM_OS2_CUI` (5): (Obsolete) OS/2 CUI subsystem
        *   `IMAGE_SUBSYSTEM_POSIX_CUI` (7): (Obsolete) POSIX CUI subsystem
        *   `IMAGE_SUBSYSTEM_WINDOWS_CE_GUI` (9): Windows CE GUI
        *   `IMAGE_SUBSYSTEM_EFI_APPLICATION` (10): EFI Application
        *   `IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER` (11): EFI Boot Service Driver
        *   `IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER` (12): EFI Runtime Driver
        *   `IMAGE_SUBSYSTEM_EFI_ROM` (13): EFI ROM Image
        *   `IMAGE_SUBSYSTEM_XBOX` (14): XBOX system
        *   `IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION` (16): Windows Boot Application
    *   **สาเหตุ-เหตุผล:** OS ใช้ข้อมูลนี้ในการจัดเตรียมสภาพแวดล้อมที่เหมาะสมสำหรับโปรแกรม (เช่น จะสร้าง console window ให้หรือไม่, จะโหลด subsystem DLLs ที่จำเป็นหรือไม่)
    *   **Cybersecurity Relevance:**
        *   Subsystem ที่ไม่ตรงกับลักษณะของโปรแกรม (เช่น โปรแกรม GUI ที่ระบุเป็น CUI หรือ Native) อาจเป็นเทคนิคหลบเลี่ยงหรือทำให้ผู้ใช้สับสน
        *   มัลแวร์ที่เป็น Native application จะทำงานในระดับที่ต่ำกว่าและอาจมีสิทธิ์สูงกว่า

12. **`DllCharacteristics` (WORD - 2 bytes):**
    *   **ความหมาย:** เป็นชุดของ bit flags ที่ระบุคุณลักษณะเพิ่มเติมของ DLL (หรือ EXE) โดยเฉพาะที่เกี่ยวข้องกับความปลอดภัยและการโหลด
    *   **ค่า Flags ที่สำคัญ (ตัวอย่าง):**
        *   `0x0020` (`IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`): Image สามารถใช้ address space ที่มี entropy สูง (64-bit ASLR)
        *   `0x0040` (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`): Image สามารถถูก relocate หรือโหลดที่ `ImageBase` แบบสุ่มได้ (ASLR compatibility) **นี่คือ flag สำคัญสำหรับ ASLR**
        *   `0x0080` (`IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`): Code Integrity checks จะถูกบังคับใช้ (ไฟล์ต้องมี digital signature ที่ถูกต้อง)
        *   `0x0100` (`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`): Image เข้ากันได้กับ Data Execution Prevention (DEP) คือ OS สามารถ mark stack และ heap เป็น non-executable ได้ **นี่คือ flag สำคัญสำหรับ DEP**
        *   `0x0200` (`IMAGE_DLLCHARACTERISTICS_NO_ISOLATION`): Image ไม่ควรถูก isolated (เกี่ยวข้องกับ SxS/Manifests, ไม่ค่อยใช้แล้ว)
        *   `0x0400` (`IMAGE_DLLCHARACTERISTICS_NO_SEH`): Image ไม่ใช้ Structured Exception Handling (SEH) (ถ้าตั้งไว้ OS จะไม่พยายามค้นหา SEH handlers จาก image นี้)
        *   `0x0800` (`IMAGE_DLLCHARACTERISTICS_NO_BIND`): ไม่ต้องทำการ bind image นี้ (เกี่ยวข้องกับ IAT binding, ไม่ค่อยใช้แล้ว)
        *   `0x1000` (`IMAGE_DLLCHARACTERISTICS_APPCONTAINER`): Image ต้องรันใน AppContainer (สำหรับ Windows Store apps)
        *   `0x2000` (`IMAGE_DLLCHARACTERISTICS_WDM_DRIVER`): Image เป็น Windows Driver Model (WDM) driver
        *   `0x4000` (`IMAGE_DLLCHARACTERISTICS_GUARD_CF`): Image รองรับ Control Flow Guard (CFG)
        *   `0x8000` (`IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE`): แอปพลิเคชันสามารถทำงานได้ดีในสภาพแวดล้อม Terminal Server
    *   **สาเหตุ-เหตุผล:** Flags เหล่านี้ช่วยให้ OS สามารถบังคับใช้ security mitigations และจัดการการโหลด image ได้อย่างเหมาะสม
    *   **Cybersecurity Relevance:**
        *   **ASLR/DEP/CFG:** การไม่ตั้งค่า flags `DYNAMIC_BASE`, `NX_COMPAT`, `GUARD_CF` ใน executables สมัยใหม่ ถือเป็น bad practice และทำให้ image นั้นๆ อ่อนแอต่อการโจมตีประเภท memory corruption มากขึ้น มัลแวร์ที่ไม่รองรับ mitigations เหล่านี้จะง่ายต่อการ exploit
        *   **FORCE_INTEGRITY:** หากตั้งค่านี้ ไฟล์นั้นจะต้อง signed อย่างถูกต้องถึงจะโหลดได้ (มักใช้กับ kernel drivers)
        *   **NO_SEH:** การตั้งค่านี้ในไฟล์ที่มี SEH handlers อยู่จริง อาจเป็นเทคนิคหลบเลี่ยงการวิเคราะห์ SEH chain

13. **`SizeOfStackReserve` (DWORD สำหรับ PE32, ULONGLONG สำหรับ PE32+):**
    *   **ความหมาย:** ขนาดของ virtual memory (เป็น bytes) ที่จะ **จอง (reserve)** ไว้สำหรับ stack ของ thread แรกที่ถูกสร้างขึ้นเมื่อ process เริ่มทำงาน
    *   **ค่าปกติ:** มักจะเป็น 1MB (0x100000)

14. **`SizeOfStackCommit` (DWORD สำหรับ PE32, ULONGLONG สำหรับ PE32+):**
    *   **ความหมาย:** ขนาดของ virtual memory (เป็น bytes) ที่จะ **คอมมิต (commit)** (คือจัดสรร physical memory หรือ page file backing ให้) สำหรับ stack ของ thread แรก ณ เวลาเริ่มต้น ค่านี้ต้องเล็กกว่าหรือเท่ากับ `SizeOfStackReserve`
    *   **ค่าปกติ:** มักจะเป็นขนาด page (เช่น 4KB หรือ 8KB)

15. **`SizeOfHeapReserve` (DWORD สำหรับ PE32, ULONGLONG สำหรับ PE32+):**
    *   **ความหมาย:** ขนาดของ virtual memory (เป็น bytes) ที่จะ **จอง (reserve)** ไว้สำหรับ default heap ของ process
    *   **ค่าปกติ:** มักจะเป็น 1MB (0x100000)

16. **`SizeOfHeapCommit` (DWORD สำหรับ PE32, ULONGLONG สำหรับ PE32+):**
    *   **ความหมาย:** ขนาดของ virtual memory (เป็น bytes) ที่จะ **คอมมิต (commit)** สำหรับ default heap ของ process ณ เวลาเริ่มต้น ค่านี้ต้องเล็กกว่าหรือเท่ากับ `SizeOfHeapReserve`
    *   **ค่าปกติ:** มักจะเป็นขนาด page สองเท่า (เช่น 8KB หรือ 16KB)

    **Cybersecurity Relevance (Stack/Heap Sizes):**
    *   ขนาดที่ใหญ่หรือเล็กผิดปกติอาจเป็นที่น่าสนใจ มัลแวร์บางตัวอาจจอง stack/heap ขนาดใหญ่เพื่อใช้เป็น buffer หรือเพื่อหลอกเครื่องมือวิเคราะห์ resource usage

17. **`LoaderFlags` (DWORD - 4 bytes):**
    *   **ความหมาย:** (Obsolete) สงวนไว้และควรเป็นศูนย์
    *   **Cybersecurity Relevance:** ถ้าไม่เป็นศูนย์ อาจเป็นสัญญาณของความผิดปกติ

18. **`NumberOfRvaAndSizes` (DWORD - 4 bytes):**
    *   **ความหมาย:** ระบุจำนวนของ entries ในอาร์เรย์ `DataDirectory` ที่ตามมา ค่านี้มีความสำคัญมาก เพราะมันบอกว่า Optional Header มี Data Directory กี่ตัว (ถึงแม้ว่าตามสเปคจะมี `IMAGE_NUMBEROF_DIRECTORY_ENTRIES` ซึ่งปัจจุบันคือ 16 entries ก็ตาม แต่ค่านี้อาจน้อยกว่า 16 ได้ ถ้า linker ไม่ได้สร้าง Data Directory ครบทุกตัว หรือในอนาคตอาจมีมากกว่า 16)
    *   **ข้อจำกัด:** ไม่สามารถมีค่ามากกว่า 16 (ณ ปัจจุบัน)
    *   **Cybersecurity Relevance:**
        *   ค่าที่มากกว่า 16 หรือไม่สอดคล้องกับจำนวน Data Directory ที่มีอยู่จริง เป็นสัญญาณของไฟล์ที่ผิดปกติหรือถูกดัดแปลง
        *   มัลแวร์อาจตั้งค่านี้ให้น้อยกว่าความเป็นจริงเพื่อซ่อน Data Directory บางตัวจากเครื่องมือวิเคราะห์ที่ไม่รอบคอบ (แต่ loader ที่ถูกต้องจะยึดตามค่านี้)

## 7.2 Data Directories (`IMAGE_DATA_DIRECTORY` Array)

ส่วนสุดท้ายของ Optional Header (และเป็นส่วนที่สำคัญมาก) คืออาร์เรย์ของโครงสร้าง `IMAGE_DATA_DIRECTORY` ปัจจุบันอาร์เรย์นี้มี 16 entries (`IMAGE_NUMBEROF_DIRECTORY_ENTRIES` = 16) แต่ละ entry ทำหน้าที่เป็น "ตัวชี้" ไปยังตารางข้อมูลหรือโครงสร้างที่สำคัญภายใน PE file

**โครงสร้างของ `IMAGE_DATA_DIRECTORY` (แต่ละ entry มีขนาด 8 bytes):**

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;  // RVA of the data structure
    DWORD   Size;            // Size in bytes of the data structure
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

**แต่ละ entry ในอาร์เรย์ `DataDirectory[16]` จะสอดคล้องกับประเภทข้อมูลที่กำหนดไว้ล่วงหน้า ดังนี้:**

| Index | Macro Name                             | คำอธิบาย                                                                 | Cybersecurity Relevance (สูงมากสำหรับหลายตัว)                                                                                                                                                                                                                                                              |
| :---- | :------------------------------------- | :----------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | `IMAGE_DIRECTORY_ENTRY_EXPORT`         | Export Table (EAT) - สำหรับ DLLs ที่ export ฟังก์ชัน/ข้อมูล             | ชี้ไปยังฟังก์ชันที่ DLL ให้บริการ มัลแวร์ (เช่น backdoor, bot) อาจ export ฟังก์ชันสำหรับ C&C หรือสำหรับ component อื่นเรียกใช้ การวิเคราะห์ EAT สำคัญมากสำหรับ DLL                                                                                                                                           |
| 1     | `IMAGE_DIRECTORY_ENTRY_IMPORT`         | Import Table (IDT/IAT) - ฟังก์ชันที่ image import มาจาก DLLs อื่น        | **สำคัญที่สุดตัวหนึ่ง** บอกว่าโปรแกรมเรียกใช้ API อะไรบ้างจาก Windows หรือ DLL อื่นๆ ซึ่งบ่งบอกถึงความสามารถของโปรแกรม/มัลแวร์ (เช่น network, file, process, registry operations) IAT hooking เป็นเทคนิคที่มัลแวร์และ Antivirus ใช้                                                                      |
| 2     | `IMAGE_DIRECTORY_ENTRY_RESOURCE`       | Resource Table - ทรัพยากรต่างๆ (icons, strings, dialogs, version info) | มัลแวร์อาจซ่อน config, payloads, หรือ script ไว้ใน resources หรืออาจมี version info ปลอมๆ หรือไม่มีเลย Strings ใน resource อาจให้เบาะแส                                                                                                                                                                    |
| 3     | `IMAGE_DIRECTORY_ENTRY_EXCEPTION`      | Exception Handling Table - ข้อมูลสำหรับการจัดการ exception (x64, IA64)  | สำหรับสถาปัตยกรรมที่ใช้ table-based exception handling (เช่น x64) การมีหรือไม่มีตารางนี้ หรือตารางที่ผิดปกติ อาจมีผลต่อการทำงานหรือการ debug                                                                                                                                                            |
| 4     | `IMAGE_DIRECTORY_ENTRY_SECURITY`       | Certificate Table (Attribute Certificate Table) - สำหรับ Digital Signatures | ชี้ไปยังข้อมูล Authenticode digital signature การตรวจสอบ signature และ certificate chain เป็นสิ่งสำคัญในการประเมินความน่าเชื่อถือของไฟล์ มัลแวร์อาจไม่มี signature, ใช้ signature ที่ถูกขโมยมา, หรือมี signature ที่ไม่ถูกต้อง                                                                      |
| 5     | `IMAGE_DIRECTORY_ENTRY_BASERELOC`      | Base Relocation Table - ข้อมูลสำหรับ relocate image ถ้า `ImageBase` ชน | ถ้า image ถูกโหลดที่ `ImageBase` อื่นที่ไม่ใช่ preferred base, loader จะใช้ตารางนี้เพื่อ patch hardcoded addresses มัลแวร์ที่ไม่มี relocation table (หรือถูก stripped) แต่ถูกคอมไพล์โดยไม่ได้รองรับ ASLR เต็มที่ อาจทำงานผิดพลาดถ้าถูก relocate หรืออาจถูกออกแบบมาให้ไม่ถูก relocate |
| 6     | `IMAGE_DIRECTORY_ENTRY_DEBUG`          | Debug Directory - ข้อมูล debug (เช่น ชี้ไปไฟล์ .PDB)                   | มัลแวร์ส่วนใหญ่มักจะ stripped debug info ออก แต่ถ้ามี อาจช่วยในการ reverse engineering ได้ ข้อมูล debug ที่ชี้ไป path แปลกๆ หรือมี type ที่ไม่ปกติก็อาจน่าสนใจ                                                                                                                                       |
| 7     | `IMAGE_DIRECTORY_ENTRY_ARCHITECTURE`   | Architecture Specific Data (สงวนไว้, ต้องเป็น 0)                       | ถ้าไม่เป็น 0 แสดงว่าผิดปกติ                                                                                                                                                                                                                                                                   |
| 8     | `IMAGE_DIRECTORY_ENTRY_GLOBALPTR`      | RVA ของ Global Pointer (GP) - (IA64, MIPS, Alpha)                      | ไม่เกี่ยวข้องกับ x86/x64 โดยตรง ถ้ามีค่าใน x86/x64 PE อาจจะแปลก                                                                                                                                                                                                                                   |
| 9     | `IMAGE_DIRECTORY_ENTRY_TLS`            | Thread Local Storage (TLS) Table - สำหรับข้อมูล TLS ของแต่ละ thread       | มัลแวร์มักใช้ TLS callbacks เพื่อรันโค้ด **ก่อน** ที่ `AddressOfEntryPoint` จะถูกเรียก (anti-debugging, anti-VM, unpacking) การตรวจสอบ TLS Table และ callbacks เป็นสิ่งสำคัญมาก                                                                                                                 |
| 10    | `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`    | Load Configuration Table - ข้อมูล config สำหรับ loader (SEH, CFG, etc.)   | มีข้อมูลเกี่ยวกับ security mitigations เช่น SafeSEH, GS (stack cookie), CFG, และอื่นๆ มัลแวร์อาจไม่มีตารางนี้ หรือมีค่าที่ปิดการใช้งาน mitigations หรือมีค่าที่ผิดปกติ                                                                                                                                  |
| 11    | `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`   | Bound Import Table - ข้อมูล DLL ที่ถูก pre-bound (ไม่ค่อยใช้แล้ว)       | การทำ Bound Import ทำให้โหลดเร็วขึ้น แต่ถ้า DLL ปลายทางเปลี่ยนไป (เช่น version) ก็ต้อง re-bind ใหม่ มัลแวร์ไม่ค่อยใช้ และถ้ามีอาจเป็นเทคนิคเก่า                                                                                                                                                  |
| 12    | `IMAGE_DIRECTORY_ENTRY_IAT`            | Import Address Table (IAT) - ตารางที่อยู่ของฟังก์ชันที่ import มาจริงๆ    | IAT คือส่วนที่ถูก loader แก้ไขให้ชี้ไปยัง address จริงของ imported functions ณ runtime และเป็นส่วนหนึ่งของ Import Table โดยปริยาย (Data Directory ตัวที่ 1 ชี้ไปยังโครงสร้างที่ครอบคลุม IAT) การมี Data Directory แยกสำหรับ IAT อาจใช้ในกรณีพิเศษ หรือบาง packer อาจใช้ชี้ไปยัง IAT ที่สร้างขึ้นใหม่ |
| 13    | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`   | Delay Load Import Descriptor - สำหรับ DLLs ที่โหลดแบบล่าช้า              | DLLs จะถูกโหลดเมื่อฟังก์ชันจาก DLL นั้นถูกเรียกใช้ครั้งแรก มัลแวร์อาจใช้เพื่อซ่อน API calls บางส่วน หรือเพื่อลด footprint ตอนเริ่มต้น                                                                                                                                                                |
| 14    | `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` | CLR Runtime Header - สำหรับ .NET executables (ชี้ไป .NET metadata)     | **สำคัญมากสำหรับ .NET malware** ชี้ไปยังโครงสร้างที่ Common Language Runtime (CLR) ใช้ในการจัดการ .NET assembly การวิเคราะห์ .NET PE ต้องใช้เครื่องมือเฉพาะ (เช่น dnSpy, ILSpy)                                                                                                              |
| 15    | (สงวนไว้, ต้องเป็น 0)                  | Reserved                                                                 | ถ้าไม่เป็น 0 แสดงว่าผิดปกติ                                                                                                                                                                                                                                                                   |

**การทำงานของ Data Directories:**
*   ถ้า `VirtualAddress` และ `Size` ของ entry หนึ่งเป็น 0 ทั้งคู่ หมายความว่า image นั้นไม่มีตารางข้อมูลประเภทนั้น
*   ถ้ามีค่า (ไม่เป็น 0) `VirtualAddress` จะเป็น RVA ที่ชี้ไปยังจุดเริ่มต้นของตารางข้อมูลนั้นๆ ใน memory (และมักจะอยู่ใน section ใด section หนึ่ง เช่น .rdata, .idata, .edata) และ `Size` จะเป็นขนาดของตารางข้อมูลนั้นเป็น bytes
*   Windows loader และเครื่องมือวิเคราะห์ PE จะใช้ RVA และ Size นี้ในการค้นหาและตีความตารางข้อมูลเหล่านั้น

## 7.3 สรุป

Optional Header เป็นส่วนที่ซับซ้อนและเต็มไปด้วยข้อมูลสำคัญสำหรับการโหลดและรัน PE file Windows-Specific Fields ให้ข้อมูลเกี่ยวกับการจัดวาง image ในหน่วยความจำ, เวอร์ชันที่ต้องการ, ขนาดต่างๆ, checksum, subsystem, และ DllCharacteristics ที่เกี่ยวข้องกับความปลอดภัย

ส่วนที่สำคัญที่สุดคือ **Data Directories** ซึ่งทำหน้าที่เป็น "สารบัญ" ชี้ไปยังโครงสร้างข้อมูลที่จำเป็น 16 ประเภท (เช่น Import Table, Export Table, Resource Table, TLS Table, .NET Header) การทำความเข้าใจว่าแต่ละ Data Directory ชี้ไปที่ใด และข้อมูลนั้นมีความหมายอย่างไร เป็นหัวใจสำคัญของการวิเคราะห์ PE file โดยเฉพาะอย่างยิ่งในงาน Cybersecurity

ในบทต่อๆ ไป เราจะเริ่มเจาะลึกเข้าไปใน Data Directories ที่สำคัญเหล่านี้ทีละตัว โดยเริ่มจาก Section Table และ Sections พื้นฐานก่อน เพื่อให้เห็นว่าข้อมูลที่ Data Directories ชี้ไปนั้น ถูกจัดเก็บไว้ที่ใดใน PE file
