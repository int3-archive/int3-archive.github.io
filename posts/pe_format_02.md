---
date: 2025-01-02
title: PE Format บทที่ 2 - ประวัติความเป็นมา และวิวัฒนาการของ PE Format
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: การทำความเข้าใจประวัติความเป็นมาและวิวัฒนาการของ Portable Executable (PE) format ช่วยให้เราเห็นภาพว่าทำไมโครงสร้างของมันจึงเป็นเช่นปัจจุบัน
---

# บทที่ 2 - ประวัติความเป็นมา และวิวัฒนาการของ PE Format

การทำความเข้าใจประวัติความเป็นมาและวิวัฒนาการของ Portable Executable (PE) format ช่วยให้เราเห็นภาพว่าทำไมโครงสร้างของมันจึงเป็นเช่นปัจจุบัน และปัจจัยใดบ้างที่มีอิทธิพลต่อการออกแบบ PE format ไม่ได้เกิดขึ้นมาในสุญญากาศ แต่เป็นผลลัพธ์ของการพัฒนาต่อยอดจาก file format รุ่นก่อนๆ เพื่อตอบสนองต่อความต้องการที่เปลี่ยนแปลงไปของระบบปฏิบัติการและสถาปัตยกรรมฮาร์ดแวร์

## 2.1 ยุคเริ่มต้น: COM Files (MS-DOS)

*   **รูปแบบ (Format):** `.COM` files (Command files)
*   **ระบบปฏิบัติการ:** MS-DOS
*   **ลักษณะเด่น:**
    *   **เรียบง่ายที่สุด:** COM file คือ "binary image" ของโปรแกรมที่ถูกโหลดเข้าสู่หน่วยความจำโดยตรงที่ offset `0x100` ภายใน segment เดียวกัน ไม่มี header ที่ซับซ้อน ไม่มีแนวคิดเรื่อง sections หรือ relocations
    *   **ขนาดจำกัด:** ขนาดสูงสุดของ COM file คือ 65,280 bytes (64KB - 256 bytes สำหรับ Program Segment Prefix - PSP)
    *   **Single Segment:** โค้ด, ข้อมูล, และ stack ทั้งหมดต้องอยู่ใน segment ขนาด 64KB เดียวกัน
    *   **ไม่มี Relocation:** โค้ดต้องเป็น position-independent หรือถูกเขียนให้ทำงานได้เมื่อโหลดที่ `0x100` เสมอ
*   **สาเหตุ-เหตุผลของการมีอยู่:**
    *   ในยุคแรกของ PC ฮาร์ดแวร์มีข้อจำกัดมาก (หน่วยความจำน้อย, CPU ช้า) รูปแบบที่เรียบง่ายและโหลดเร็วจึงเหมาะสม
    *   MS-DOS เป็นระบบปฏิบัติการแบบ single-tasking และมี memory model ที่ไม่ซับซ้อน
*   **ข้อจำกัดที่นำไปสู่การพัฒนาต่อ:**
    *   ขนาดโปรแกรมที่จำกัดมาก ไม่เพียงพอสำหรับแอปพลิเคชันที่ซับซ้อนขึ้น
    *   การจัดการหน่วยความจำที่ตายตัว ไม่ยืดหยุ่น
    *   ไม่รองรับ code/data sharing หรือ dynamic linking

## 2.2 ก้าวแรกสู่ความซับซ้อน: MZ Executables (MS-DOS)

*   **รูปแบบ (Format):** `.EXE` files (MZ Executables)
*   **ระบบปฏิบัติการ:** MS-DOS, Windows (สำหรับ backward compatibility)
*   **ลักษณะเด่น:**
    *   **MZ Signature:** ไฟล์เริ่มต้นด้วยตัวอักษร "MZ" (ASCII 0x4D, 0x5A) ซึ่งเป็นชื่อย่อของ Mark Zbikowski หนึ่งในสถาปนิกของ MS-DOS และเป็นผู้พัฒนา format นี้
    *   **EXE Header:** มี header ที่ให้ข้อมูลพื้นฐานเกี่ยวกับโปรแกรม เช่น ขนาดไฟล์, checksum, ตำแหน่งของ relocation table, ค่าเริ่มต้นของ CS:IP (Code Segment:Instruction Pointer) และ SS:SP (Stack Segment:Stack Pointer)
    *   **Relocation Table:** รองรับการทำ relocation ทำให้โค้ดสามารถถูกโหลดในตำแหน่งต่างๆ ในหน่วยความจำได้ โปรแกรมไม่จำเป็นต้องเป็น position-independent ทั้งหมด linker จะสร้างตาราง relocation เพื่อให้ OS loader ปรับปรุง address references ตอนโหลด
    *   **Multiple Segments:** โปรแกรมสามารถใช้หลาย code segments และ data segments ได้ ทำให้สามารถสร้างโปรแกรมขนาดใหญ่กว่า 64KB ได้
*   **สาเหตุ-เหตุผลของการพัฒนา:**
    *   ความต้องการโปรแกรมที่มีขนาดใหญ่และซับซ้อนกว่า COM files
    *   ต้องการความยืดหยุ่นในการจัดการหน่วยความจำมากขึ้น แม้จะยังคงอยู่ใน Real Mode ของสถาปัตยกรรม x86
*   **ข้อจำกัดที่ยังคงอยู่และนำไปสู่การพัฒนาต่อ:**
    *   ยังคงเป็น 16-bit format เหมาะสำหรับ Real Mode หรือ Virtual 8086 mode
    *   ไม่รองรับ Protected Mode features ของ CPU (เช่น virtual memory, memory protection) โดยตรง
    *   การจัดการ DLLs หรือ shared libraries ยังไม่มีประสิทธิภาพ
    *   ไม่มีการแบ่งแยก sections อย่างชัดเจน (เช่น .text, .data)

## 2.3 ยุคของ Windows 16-bit: New Executable (NE) Format

*   **รูปแบบ (Format):** `.EXE`, `.DLL` (NE Executables)
*   **ระบบปฏิบัติการ:** Windows 16-bit (Windows 1.x, 2.x, 3.x), OS/2 1.x
*   **ลักษณะเด่น:**
    *   **NE Signature:** ไฟล์ NE ยังคงมี MZ header เดิมเพื่อ backward compatibility (MS-DOS stub program) แต่จะมี offset ชี้ไปยัง "NE" signature (ASCII 0x4E, 0x45) และ NE header
    *   **ออกแบบสำหรับ Protected Mode:** รองรับการทำงานใน Protected Mode ของ Intel 80286 และใหม่กว่า
    *   **Segments และ Selectors:** จัดการหน่วยความจำผ่าน segments และ selectors แทนที่ physical addresses
    *   **Resource Support:** มีการสนับสนุนทรัพยากร (resources) ของโปรแกรมอย่างเป็นทางการ เช่น icons, cursors, dialog boxes, strings
    *   **Entry Table และ Resident/Non-Resident Name Tables:** สำหรับการจัดการ exports และ imports ของ DLLs
    *   **Multiple Code/Data Segments:** รองรับหลาย segments ที่มีคุณสมบัติต่างกัน (เช่น movable, discardable)
*   **สาเหตุ-เหตุผลของการพัฒนา:**
    *   Windows เป็นระบบปฏิบัติการแบบ graphical user interface (GUI) และ multitasking (cooperative multitasking) ซึ่งต้องการ memory management ที่ซับซ้อนกว่า MS-DOS
    *   ต้องการรองรับ DLLs อย่างมีประสิทธิภาพเพื่อ code sharing และ modularity
    *   การใช้ Protected Mode ของ CPU เพื่อเข้าถึงหน่วยความจำได้มากขึ้นและมี memory protection
*   **ข้อจำกัดที่นำไปสู่การพัฒนาต่อ:**
    *   ยังคงเป็น 16-bit format ซึ่งมีข้อจำกัดด้าน address space (แม้จะใช้ segments ก็ตาม)
    *   ไม่เหมาะสำหรับสถาปัตยกรรม 32-bit ที่กำลังจะมาถึง (Intel 80386)
    *   โครงสร้างยังค่อนข้างซับซ้อนและจัดการยากในบางส่วน

## 2.4 การเปลี่ยนผ่านและการรองรับ OS/2: Linear Executable (LE & LX) Format

*   **รูปแบบ (Format):** `.EXE`, `.DLL` (LE/LX Executables)
*   **ระบบปฏิบัติการ:** OS/2 2.x (32-bit), Windows 3.x (Win32s extension), Windows 9x (VxDs)
*   **ลักษณะเด่น (LE):**
    *   **LE Signature:** ต่อจาก MZ stub, มี "LE" signature
    *   **32-bit Addressing (Flat Model):** ออกแบบมาสำหรับ 32-bit protected mode และ "flat" memory model (ถึงแม้ OS/2 2.x ยังคงใช้ segmented memory model สำหรับ 16-bit compatibility)
    *   **Object-based:** แทนที่จะเป็น segment-based เหมือน NE, LE จัดการโค้ดและข้อมูลเป็น "objects" (คล้ายกับ sections ใน PE) แต่ละ object มีคุณสมบัติ (read, write, execute)
    *   **Fixup Table:** ระบบ relocation ที่ซับซ้อนกว่าเดิม รองรับ fixups ประเภทต่างๆ
    *   **Page-based:** ข้อมูลถูกจัดเรียงเป็น page เพื่อให้สอดคล้องกับ virtual memory management ของ OS
*   **LX Format (Linear eXecutable, variant of LE):** ใช้ใน OS/2 2.0 และใหม่กว่า มีการปรับปรุงเพิ่มเติม
*   **สาเหตุ-เหตุผลของการพัฒนา:**
    *   การมาถึงของ CPU 32-bit (Intel 80386) และความต้องการใช้ประโยชน์จาก flat memory model และ virtual memory อย่างเต็มที่
    *   OS/2 เป็นระบบปฏิบัติการ 32-bit ที่ต้องการ executable format ที่ทันสมัยกว่า NE
    *   Windows 9x ใช้ LE/LX format สำหรับ Virtual Device Drivers (VxDs)
*   **ข้อจำกัดและทิศทางสู่ PE:**
    *   ถึงแม้ LE/LX จะเป็น 32-bit แต่ก็ยังผูกกับ OS/2 และไม่ "portable" ข้ามสถาปัตยกรรม CPU อื่นๆ (เช่น MIPS, Alpha ที่ Windows NT ตั้งเป้าจะรองรับ)
    *   Microsoft ต้องการ format เดียวที่สามารถใช้ได้ทั้งบน Windows NT (ที่กำลังพัฒนา) และ Windows 9x (ในระดับหนึ่ง) และรองรับหลาย CPU architectures

## 2.5 กำเนิดของ Portable Executable (PE) Format

*   **รูปแบบ (Format):** `.EXE`, `.DLL`, `.SYS`, etc. (PE Executables)
*   **ระบบปฏิบัติการ:** Windows NT (เริ่มต้นด้วย NT 3.1), Windows 95, และ Windows ทุกเวอร์ชันหลังจากนั้น
*   **ลักษณะเด่น:**
    *   **พื้นฐานจาก COFF (Common Object File Format):** PE format ได้รับการพัฒนาต่อยอดมาจาก COFF ซึ่งเป็น format ที่ใช้ในระบบ Unix และ VMS COFF ให้โครงสร้างพื้นฐานสำหรับ object files และ executables รวมถึงแนวคิดเรื่อง sections, symbol table, และ relocation information
    *   **MZ Stub และ PE Signature:** ยังคงมี MZ header และ DOS stub program เพื่อ backward compatibility และแสดงข้อความ "This program cannot be run in DOS mode." หากพยายามรันบน MS-DOS offset `e_lfanew` ใน MZ header จะชี้ไปยังตำแหน่งของ "PE\0\0" signature (ASCII 0x50, 0x45, 0x00, 0x00)
    *   **COFF File Header:** ประกอบด้วยข้อมูลทั่วไปเกี่ยวกับไฟล์ เช่น target machine (สถาปัตยกรรม CPU), จำนวน sections, timestamp
    *   **Optional Header:** นี่คือหัวใจสำคัญของ PE format ประกอบด้วยข้อมูลมากมายที่จำเป็นสำหรับการโหลดและรันโปรแกรม เช่น entry point, image base address, sizes of code/data, subsystem, DLL characteristics, และที่สำคัญคือ **Data Directories**
    *   **Data Directories:** Array ของโครงสร้างที่ชี้ไปยังตารางข้อมูลสำคัญต่างๆ เช่น Export Table, Import Table, Resource Table, Relocation Table, Debug Directory, TLS Table, Load Config Table, IAT เป็นต้น ทำให้ format มีความยืดหยุ่นและขยายได้
    *   **Section Table และ Sections:** กำหนดส่วนต่างๆ ของโปรแกรมในหน่วยความจำ (เช่น `.text` สำหรับโค้ด, `.data` สำหรับ initialized data, `.rdata` สำหรับ read-only data, `.bss` สำหรับ uninitialized data) แต่ละ section มีชื่อ, ขนาด, ตำแหน่งในไฟล์, ตำแหน่งในหน่วยความจำ (RVA), และคุณสมบัติ (read, write, execute)
    *   **Portability:** ออกแบบมาเพื่อรองรับหลายสถาปัตยกรรม CPU (x86, MIPS, Alpha, PowerPC ในยุคแรกๆ ของ NT; ต่อมาเป็น x64, ARM, ARM64) โดยการเปลี่ยนค่าใน COFF File Header (Machine field) และการปรับขนาดของบางฟิลด์ใน Optional Header (PE32 สำหรับ 32-bit, PE32+ สำหรับ 64-bit)
*   **สาเหตุ-เหตุผลของการพัฒนา:**
    *   Windows NT ถูกออกแบบมาเป็น OS ที่ "portable" ข้ามสถาปัตยกรรม CPU และมีความปลอดภัยสูง จึงต้องการ executable format ที่รองรับคุณสมบัติเหล่านี้
    *   ต้องการ format ที่รองรับ 32-bit และ 64-bit addressing อย่างเต็มรูปแบบ, virtual memory, memory protection, และ dynamic linking ที่มีประสิทธิภาพ
    *   ต้องการรวมคุณสมบัติที่ดีของ format ก่อนหน้า (เช่น resource support จาก NE, object/section-based จาก LE/COFF) เข้าไว้ด้วยกันใน format ที่เป็นมาตรฐานเดียว
    *   COFF เป็น format ที่ได้รับการยอมรับและพิสูจน์แล้วในระบบอื่น Microsoft จึงนำมาปรับปรุงและขยายเพื่อให้เหมาะสมกับ Windows

## 2.6 วิวัฒนาการของ PE Format ภายในยุค Windows สมัยใหม่

แม้ว่าโครงสร้างหลักของ PE format จะค่อนข้างคงที่นับตั้งแต่ Windows NT 3.1 แต่ก็มีการเพิ่มเติมและปรับปรุงเล็กน้อยเพื่อรองรับคุณสมบัติใหม่ๆ ของ Windows และเทคโนโลยีความปลอดภัย:

*   **PE32+:** การขยาย Optional Header เพื่อรองรับ 64-bit addressing (สำหรับ x64, IA64, ARM64) เช่น ImageBase และ SizeOfStackReserve/Commit กลายเป็น 64-bit values
*   **Data Directory Entries ใหม่ๆ:**
    *   **.NET Runtime Header (CLR Header):** สำหรับ managed executables (.NET applications) ชี้ไปยัง metadata ที่จำเป็นสำหรับ Common Language Runtime (CLR)
    *   **Security Directory:** สำหรับ Authenticode digital signatures เพื่อตรวจสอบความสมบูรณ์และแหล่งที่มาของไฟล์
    *   **Load Configuration Directory:** ขยายเพิ่มเติมเพื่อรองรับคุณสมบัติความปลอดภัย เช่น Structured Exception Handling (SEH) protection (SafeSEH), Control Flow Guard (CFG), Address Space Layout Randomization (ASLR) flags (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`), Data Execution Prevention (DEP) compatibility (`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`)
    *   **Delay Load Import Descriptor:** สำหรับการโหลด DLLs แบบ "ล่าช้า" (delay-loaded DLLs) คือ DLL จะถูกโหลดเข้าหน่วยความจำเมื่อฟังก์ชันจาก DLL นั้นถูกเรียกใช้ครั้งแรกจริงๆ
*   **Section Flags ใหม่ๆ:** เช่น `IMAGE_SCN_MEM_PROTECTED` (สำหรับ protected processes ใน Windows ที่ใหม่กว่า)
*   **การรองรับเทคนิค Mitigation สมัยใหม่:** หลายๆ ฟิลด์ใน Optional Header (โดยเฉพาะใน `DllCharacteristics` และ Load Configuration Directory) ถูกใช้เพื่อระบุว่า executable นั้น compile มาพร้อมกับ security mitigations ใดบ้าง และ OS ควรบังคับใช้ mitigations เหล่านั้นอย่างไร

## 2.7 สรุป

ประวัติศาสตร์ของ PE format สะท้อนให้เห็นถึงการปรับตัวของ Microsoft ต่อการเปลี่ยนแปลงทางเทคโนโลยีฮาร์ดแวร์และซอฟต์แวร์ จาก COM file ที่เรียบง่ายในยุค MS-DOS สู่ MZ executable, NE format สำหรับ Windows 16-bit, LE/LX สำหรับ OS/2 และ 32-bit ยุคแรก และท้ายที่สุดคือ PE format ที่ทรงพลังและยืดหยุ่นสำหรับ Windows NT และเวอร์ชันต่อๆ มา

การเข้าใจวิวัฒนาการนี้ช่วยให้เรา:
1.  **เห็นคุณค่าของโครงสร้างปัจจุบัน:** หลายส่วนของ PE header (เช่น MZ stub) มีอยู่เพื่อ backward compatibility
2.  **เข้าใจเหตุผลเบื้องหลังการออกแบบ:** เช่น การมี Data Directories ทำให้ format ขยายได้ง่าย
3.  **ตระหนักถึงความสำคัญของ PE format:** ในฐานะที่เป็นรากฐานของ software ecosystem บน Windows มาอย่างยาวนาน

ในบทต่อไป เราจะเริ่มเจาะลึกโครงสร้างหลักของ PE file โดยรวม เพื่อให้เห็นภาพว่าส่วนประกอบต่างๆ ที่กล่าวถึงในประวัติศาสตร์นี้ เชื่อมโยงกันอย่างไรในไฟล์ PE หนึ่งไฟล์
