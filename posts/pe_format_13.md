---
date: 2025-01-13
title: PE Format บทที่ 13 - ความแตกต่างระหว่าง PE32 และ PE32+ (64-bit)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: เพื่อให้สามารถจัดการกับ address space ที่ใหญ่ขึ้นและความแตกต่างของขนาดข้อมูลในสถาปัตยกรรม 64-bit ได้อย่างเหมาะสม จึงมีการปรับปรุงและขยาย PE format เล็กน้อยสำหรับ executables 64-bit
---

# บทที่ 13 - ความแตกต่างระหว่าง PE32 และ PE32+ (64-bit)

PE (Portable Executable) format ถูกออกแบบมาให้มีความ "portable" ในระดับหนึ่ง โดยสามารถรองรับได้ทั้งสถาปัตยกรรม 32-bit และ 64-bit ของ Windows อย่างไรก็ตาม เพื่อให้สามารถจัดการกับ address space ที่ใหญ่ขึ้นและความแตกต่างของขนาดข้อมูลในสถาปัตยกรรม 64-bit ได้อย่างเหมาะสม จึงมีการปรับปรุงและขยาย PE format เล็กน้อยสำหรับ executables 64-bit

*   **PE32:** เป็นชื่อเรียกทั่วไปสำหรับ PE format ที่ใช้กับ executables 32-bit (เช่น สำหรับสถาปัตยกรรม x86)
*   **PE32+:** เป็นชื่อเรียกอย่างเป็นทางการสำหรับ PE format ที่ใช้กับ executables 64-bit (เช่น สำหรับสถาปัตยกรรม x64/AMD64, IA64, ARM64) คำว่า "+" สื่อถึงการ "ขยาย" (extended) จาก PE32

แม้ว่าโครงสร้างโดยรวมของ PE32 และ PE32+ จะคล้ายคลึงกันมาก แต่ก็มีความแตกต่างที่สำคัญหลายประการ โดยเฉพาะในส่วนของ **Optional Header**

## 13.1 การระบุประเภท Image (PE32 vs PE32+)

จุดแรกที่บ่งบอกความแตกต่างคือฟิลด์ `Magic` ใน Optional Header:

*   **PE32:** ฟิลด์ `Magic` (WORD) ใน `IMAGE_OPTIONAL_HEADER32` จะมีค่า `0x010b`
*   **PE32+:** ฟิลด์ `Magic` (WORD) ใน `IMAGE_OPTIONAL_HEADER64` จะมีค่า `0x020b`

ค่า `Magic` นี้จะเป็นตัวกำหนดว่า Windows loader และเครื่องมือวิเคราะห์ PE จะต้องตีความโครงสร้าง Optional Header ที่เหลือ (และส่วนอื่นๆ ที่เกี่ยวข้อง) อย่างไร

นอกจากนี้ ฟิลด์ `Machine` ใน `IMAGE_FILE_HEADER` (COFF File Header) ก็จะระบุสถาปัตยกรรมเป้าหมาย ซึ่งควรจะสอดคล้องกับค่า `Magic` นี้:
*   ถ้า `Machine` เป็น `IMAGE_FILE_MACHINE_I386` (0x014c), `Magic` ควรเป็น `0x010b` (PE32)
*   ถ้า `Machine` เป็น `IMAGE_FILE_MACHINE_AMD64` (0x8664) หรือ `IMAGE_FILE_MACHINE_IA64` (0x0200) หรือ `IMAGE_FILE_MACHINE_ARM64` (0xaa64), `Magic` ควรเป็น `0x020b` (PE32+)

## 13.2 ความแตกต่างใน Optional Header

ความแตกต่างส่วนใหญ่ระหว่าง PE32 และ PE32+ อยู่ใน Optional Header (`IMAGE_OPTIONAL_HEADER32` vs `IMAGE_OPTIONAL_HEADER64`)

**ตารางเปรียบเทียบฟิลด์ใน Optional Header ที่แตกต่างกัน:**

| ฟิลด์ใน Optional Header         | ประเภทใน PE32 (IMAGE_OPTIONAL_HEADER32) | ประเภทใน PE32+ (IMAGE_OPTIONAL_HEADER64) | ขนาด (bytes) PE32 | ขนาด (bytes) PE32+ | คำอธิบายความแตกต่าง                                                                                                                                                                                                                                                           |
| :---------------------------- | :------------------------------------ | :------------------------------------- | :--------------- | :---------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Magic`                       | `WORD`                                | `WORD`                                 | 2                | 2                 | `0x010b` สำหรับ PE32, `0x020b` สำหรับ PE32+                                                                                                                                                                                                                                  |
| `BaseOfData`                  | `DWORD`                               | **ไม่มีฟิลด์นี้**                       | 4                | 0                 | PE32 มีฟิลด์ `BaseOfData` (RVA ของ data section) แต่ PE32+ **ไม่มี** ฟิลด์นี้ เหตุผลคือใน 64-bit memory model, code และ data ไม่จำเป็นต้องมี "base" ที่แยกจากกันอย่างชัดเจนเหมือนใน 32-bit                                                                                      |
| `ImageBase`                   | `DWORD`                               | `ULONGLONG`                            | 4                | 8                 | ใน PE32+, `ImageBase` (preferred load address) เป็นค่า 64-bit เพื่อรองรับ address space ที่ใหญ่ขึ้น (ถึงแม้ในทางปฏิบัติ `ImageBase` ส่วนใหญ่มักจะยังอยู่ใน 32-bit range ล่างๆ เพื่อความเข้ากันได้หรือลด fragmentation แต่ format รองรับค่า 64-bit เต็ม)                  |
| `SizeOfStackReserve`          | `DWORD`                               | `ULONGLONG`                            | 4                | 8                 | ขนาด stack ที่จอง (reserve) เป็น 64-bit ใน PE32+                                                                                                                                                                                                                           |
| `SizeOfStackCommit`           | `DWORD`                               | `ULONGLONG`                            | 4                | 8                 | ขนาด stack ที่คอมมิต (commit) เป็น 64-bit ใน PE32+                                                                                                                                                                                                                           |
| `SizeOfHeapReserve`           | `DWORD`                               | `ULONGLONG`                            | 4                | 8                 | ขนาด heap ที่จอง (reserve) เป็น 64-bit ใน PE32+                                                                                                                                                                                                                            |
| `SizeOfHeapCommit`            | `DWORD`                               | `ULONGLONG`                            | 4                | 8                 | ขนาด heap ที่คอมมิต (commit) เป็น 64-bit ใน PE32+                                                                                                                                                                                                                           |
| **ขนาดรวมของ Optional Header** |                                       |                                        | **224 bytes**    | **240 bytes**     | เนื่องจาก `BaseOfData` หายไป (ลด 4 bytes) แต่ 5 ฟิลด์ (`ImageBase`, `SizeOfStackReserve/Commit`, `SizeOfHeapReserve/Commit`) ขยายจาก 4 bytes เป็น 8 bytes (เพิ่ม 5 * 4 = 20 bytes) ดังนั้นขนาดรวมของ Optional Header ใน PE32+ จึงใหญ่กว่า PE32 อยู่ 16 bytes |

**ฟิลด์อื่นๆ ใน Optional Header ที่เหมือนกัน:**
ฟิลด์ที่เหลือส่วนใหญ่ใน Optional Header (เช่น `AddressOfEntryPoint`, `SectionAlignment`, `FileAlignment`, `SizeOfImage`, `SizeOfHeaders`, `Subsystem`, `DllCharacteristics`, `NumberOfRvaAndSizes`, และ `DataDirectory` array) ยังคงมี **ขนาดและประเภทข้อมูลเหมือนเดิม** ทั้งใน PE32 และ PE32+
*   ตัวอย่างเช่น `AddressOfEntryPoint` ยังคงเป็น `DWORD` (RVA 32-bit) ทั้งคู่
*   `DataDirectory` array ยังคงมี 16 entries โดยแต่ละ entry (`IMAGE_DATA_DIRECTORY`) ประกอบด้วย `DWORD VirtualAddress` (RVA) และ `DWORD Size`

**สาเหตุ-เหตุผลของการเปลี่ยนแปลง:**
*   การขยาย `ImageBase` เป็น 64-bit เพื่อรองรับ address space ที่ใหญ่ขึ้นของสถาปัตยกรรม 64-bit
*   การขยาย `SizeOfStackReserve/Commit` และ `SizeOfHeapReserve/Commit` เป็น 64-bit ก็เพื่อให้สามารถจอง/คอมมิต stack และ heap ที่มีขนาดใหญ่กว่า 4GB ได้ (แม้ในทางปฏิบัติจะไม่ค่อยเห็น stack/heap ใหญ่ขนาดนั้นสำหรับ process เดียว)
*   การตัด `BaseOfData` ออกไปใน PE32+ สะท้อนถึง memory model ที่ยืดหยุ่นกว่าใน 64-bit ซึ่งไม่จำเป็นต้องมี "data segment" ที่ตายตัว

## 13.3 โครงสร้าง `IMAGE_THUNK_DATA` (สำหรับ Imports/Exports)

เมื่อจัดการกับ Import Table (IAT, ILT/INT) หรือ Export Table (EAT), โครงสร้าง `IMAGE_THUNK_DATA` ที่ใช้เก็บ RVA หรือ address จะมีขนาดแตกต่างกัน:
*   **PE32:** ใช้ `IMAGE_THUNK_DATA32` ซึ่งเป็น `DWORD` (4 bytes)
*   **PE32+:** ใช้ `IMAGE_THUNK_DATA64` ซึ่งเป็น `ULONGLONG` (8 bytes)

นี่เป็นสิ่งสำคัญ เพราะเมื่อ loader resolve IAT ใน PE32+, มันจะเขียน Virtual Address (VA) ขนาด 64-bit ลงใน IAT entries

## 13.4 Base Relocations

ประเภทของ Base Relocation ที่ใช้ก็แตกต่างกัน:
*   **PE32:** ประเภท relocation ที่พบบ่อยที่สุดคือ `IMAGE_REL_BASED_HIGHLOW` (type 3) ซึ่งใช้ patch ค่า DWORD (32-bit) เต็มๆ
*   **PE32+:** ประเภท relocation ที่พบบ่อยที่สุดคือ `IMAGE_REL_BASED_DIR64` (type 10) ซึ่งใช้ patch ค่า ULONGLONG (64-bit) เต็มๆ

## 13.5 ขนาด Pointer และ Data Types

โดยธรรมชาติแล้ว สถาปัตยกรรม 64-bit จะใช้ pointers ขนาด 64-bit ซึ่งมีผลต่อ:
*   ขนาดของ stack frames
*   ขนาดของโครงสร้างข้อมูลที่โปรแกรมใช้
*   การ alignment ของข้อมูล

ถึงแม้ว่า PE format เองจะพยายาม abstract ความแตกต่างเหล่านี้ในระดับ header แต่โค้ดและข้อมูลภายใน sections จะสะท้อนความเป็น 64-bit อย่างชัดเจน

## 13.6 WoW64 (Windows 32-bit on Windows 64-bit)

ระบบปฏิบัติการ Windows 64-bit มี subsystem ที่เรียกว่า WoW64 ซึ่งช่วยให้โปรแกรม 32-bit (PE32) สามารถทำงานบน OS 64-bit ได้:
*   WoW64 จะสร้างสภาพแวดล้อม 32-bit เสมือนให้โปรแกรม PE32 นั้นๆ
*   โปรแกรม PE32 จะเห็น address space แค่ 2GB หรือ 3GB/4GB (ถ้า large address aware) เหมือนรันบน OS 32-bit
*   การเรียก API ของ Windows จากโปรแกรม PE32 จะถูก "thunked" (แปลง) โดย WoW64 เพื่อให้สามารถเรียก API 64-bit ของ OS จริงได้
*   **สำคัญ:** โปรแกรม PE32 **ไม่สามารถ** โหลด DLL ที่เป็น PE32+ ได้โดยตรง และโปรแกรม PE32+ ก็ **ไม่สามารถ** โหลด DLL ที่เป็น PE32 ได้โดยตรงเช่นกัน (จะต้องมีการทำ inter-process communication หรือ COM ถ้าต้องการสื่อสารกัน)

## 13.7 Cybersecurity Relevance ของความแตกต่าง

1.  **การวิเคราะห์มัลแวร์ที่ถูกต้องตามสถาปัตยกรรม:**
    *   จำเป็นต้องใช้ disassembler, debugger, และเครื่องมือวิเคราะห์ที่เหมาะสมกับสถาปัตยกรรมของ PE file (32-bit หรือ 64-bit)
    *   การวิเคราะห์มัลแวร์ 64-bit อาจมีความซับซ้อนกว่าเล็กน้อยเนื่องจาก address space ที่ใหญ่ขึ้นและ instruction set ที่แตกต่าง (เช่น x64 มี registers มากกว่า x86)

2.  **มัลแวร์แบบ Multi-Architecture:**
    *   มัลแวร์บางตัวอาจมี "dropper" หรือ "loader" ที่สามารถตรวจจับสถาปัตยกรรมของ OS แล้ว drop/load payload ที่เป็น PE32 หรือ PE32+ ที่เหมาะสม
    *   ไฟล์ PE "fat binary" (ที่มีทั้งโค้ด 32-bit และ 64-bit ในไฟล์เดียว) ไม่ใช่มาตรฐานของ PE format บน Windows (ต่างจาก Mach-O บน macOS)

3.  **Exploitation บน 64-bit:**
    *   เทคนิคการ exploit บน 64-bit อาจแตกต่างจาก 32-bit เช่น การใช้ ROP (Return-Oriented Programming) บน x64 จะมี gadgets (โค้ดชิ้นเล็กๆ ที่ใช้ในการสร้าง ROP chain) ที่แตกต่างกัน และการจัดการกับ pointers 64-bit
    *   ASLR บน 64-bit มี entropy ที่สูงกว่า (มี address space ให้สุ่มได้มากกว่า) ทำให้การ bypass ASLR ยากขึ้น

4.  **WoW64 และการตรวจจับ:**
    *   มัลแวร์ 32-bit ที่รันภายใต้ WoW64 อาจพยายามตรวจจับว่าตัวเองกำลังรันในสภาพแวดล้อม WoW64 หรือไม่ เพื่อเปลี่ยนพฤติกรรมหรือหลบเลี่ยงการวิเคราะห์ (เช่น WoW64 มี "Heaven's Gate" ที่ใช้สลับระหว่าง 32-bit และ 64-bit mode)
    *   Security software ที่ทำงานบน OS 64-bit จะต้องสามารถ monitor และวิเคราะห์ process 32-bit ที่รันภายใต้ WoW64 ได้อย่างถูกต้องด้วย

5.  **Patching และ Code Injection:**
    *   การ patch PE file หรือการทำ code injection เข้าไปใน process 64-bit จะต้องใช้โค้ดและ addresses ที่เป็น 64-bit
    *   ขนาดของคำสั่ง (opcodes) บางอย่างอาจแตกต่างกันเล็กน้อยระหว่าง x86 และ x64

## 13.8 สรุป

PE32 และ PE32+ มีโครงสร้างพื้นฐานที่คล้ายกันมาก ทำให้ PE format ยังคงความเป็น "Portable" ในระดับสูง ความแตกต่างหลักๆ อยู่ที่ Optional Header ซึ่ง PE32+ มีการขยายขนาดของฟิลด์ที่เกี่ยวข้องกับ addresses และขนาดหน่วยความจำ (เช่น `ImageBase`, `SizeOfStack/Heap Reserve/Commit`) ให้เป็น 64-bit และมีการตัดฟิลด์ `BaseOfData` ออกไป นอกจากนี้ ขนาดของ `IMAGE_THUNK_DATA` และประเภทของ Base Relocation ที่ใช้ก็แตกต่างกันเพื่อให้สอดคล้องกับสถาปัตยกรรม 64-bit

การทำความเข้าใจความแตกต่างเหล่านี้เป็นสิ่งสำคัญสำหรับนักพัฒนา, นักวิเคราะห์มัลแวร์, และผู้เชี่ยวชาญด้าน Cybersecurity เพื่อให้สามารถทำงานกับ PE files ทั้ง 32-bit และ 64-bit ได้อย่างถูกต้อง และเพื่อตระหนักถึงผลกระทบที่สถาปัตยกรรมมีต่อพฤติกรรมของโปรแกรม, เทคนิคการโจมตี, และการป้องกัน

ในส่วนถัดไปของหนังสือ เราจะเริ่มเข้าสู่ ส่วนที่ 3: PE Format และกระบวนการทำงานของระบบปฏิบัติการ โดยเริ่มจาก **กระบวนการโหลด PE File เข้าสู่หน่วยความจำ (PE Loading Process)**
