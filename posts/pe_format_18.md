---
date: 2025-01-18
title: PE Format บทที่ 18 - การใช้ PE Format ในการทำ Reverse Engineering และการวิเคราะห์ช่องโหว่
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: Reverse Engineering (วิศวกรรมย้อนกลับ) และ Vulnerability Analysis (การวิเคราะห์ช่องโหว่)
---

# บทที่ 18 - การใช้ PE Format ในการทำ Reverse Engineering และการวิเคราะห์ช่องโหว่

ความรู้ความเข้าใจในโครงสร้าง Portable Executable (PE) format ไม่ได้มีประโยชน์เพียงแค่การวิเคราะห์มัลแวร์แบบ static หรือการทำความเข้าใจกระบวนการโหลดโปรแกรมเท่านั้น แต่มันยังเป็นรากฐานที่สำคัญอย่างยิ่งสำหรับงาน **Reverse Engineering (วิศวกรรมย้อนกลับ)** และ **Vulnerability Analysis (การวิเคราะห์ช่องโหว่)**

ในบทนี้ เราจะสำรวจว่าข้อมูลจาก PE format ถูกนำมาใช้ในสองสาขานี้อย่างไร และทำไมนักวิจัยด้านความปลอดภัยจึงต้องมีความเชี่ยวชาญในเรื่องนี้

## 18.1 Reverse Engineering และ PE Format

**Reverse Engineering (RE)** ในบริบทของซอฟต์แวร์ คือกระบวนการวิเคราะห์โปรแกรมคอมพิวเตอร์เพื่อทำความเข้าใจการออกแบบ, การทำงาน, และอัลกอริทึมของมัน โดยส่วนใหญ่มักจะทำเมื่อไม่มี source code ต้นฉบับ เป้าหมายอาจมีหลากหลาย เช่น:
*   ทำความเข้าใจพฤติกรรมของมัลแวร์
*   ตรวจสอบการละเมิดลิขสิทธิ์
*   หาช่องโหว่ความปลอดภัย
*   สร้างโปรแกรมที่ทำงานร่วมกันได้ (interoperability)
*   เรียนรู้เทคนิคการเขียนโปรแกรม

PE format ให้ "แผนที่" (map) หรือ "พิมพ์เขียว" (blueprint) เริ่มต้นสำหรับการทำ RE กับโปรแกรมบน Windows:

1.  **การเริ่มต้น Disassembly และ Decompilation:**
    *   **AddressOfEntryPoint (OEP):** นี่คือจุดเริ่มต้นที่สำคัญที่สุด Disassembler (เช่น IDA Pro, Ghidra, Radare2) จะเริ่มวิเคราะห์โค้ดจาก RVA นี้ (แปลงเป็น VA โดยใช้ `ImageBase`)
    *   **Section Table (`.text` section):** `VirtualAddress` และ `VirtualSize` ของ `.text` section (หรือ sections อื่นที่มี `IMAGE_SCN_CNT_CODE` และ `IMAGE_SCN_MEM_EXECUTE` flags) จะบอก disassembler ว่าขอบเขตของโค้ดที่ประมวลผลได้อยู่ที่ใดบ้าง
    *   **BaseOfCode:** ให้ RVA เริ่มต้นของส่วนที่เป็นโค้ด

2.  **การทำความเข้าใจการเรียก API (Imports):**
    *   **Import Address Table (IAT):** เมื่อ disassembler เจอ indirect call/jump ผ่านทาง IAT มันสามารถ resolve การเรียกนั้นไปยังชื่อ API ที่ import มาได้ (ถ้า IAT ถูกเติมอย่างถูกต้อง) ช่วยให้เข้าใจว่าโปรแกรมกำลังเรียกใช้ฟังก์ชันอะไรของ Windows หรือ DLL อื่น ซึ่งเป็นกุญแจสำคัญในการทำความเข้าใจพฤติกรรม
    *   **Import Directory Table:** ให้ข้อมูลเกี่ยวกับ DLLs ที่โปรแกรมพึ่งพา

3.  **การทำความเข้าใจฟังก์ชันที่ DLL ให้บริการ (Exports) (กรณี RE ไฟล์ DLL):**
    *   **Export Address Table (EAT):** สำหรับไฟล์ DLL, EAT จะให้ RVA ของฟังก์ชันที่ DLL นั้น export นัก RE สามารถเริ่มวิเคราะห์จากฟังก์ชันที่ export เหล่านี้เพื่อทำความเข้าใจว่า DLL ทำอะไรได้บ้าง
    *   **Export Name Pointer Table / Export Ordinal Table:** ช่วยในการ map ชื่อหรือ ordinal ไปยัง RVA ของฟังก์ชันที่ export

4.  **การระบุตำแหน่งข้อมูล (Data Sections):**
    *   **`.data`, `.rdata`, `.bss` sections:** `VirtualAddress` และ `VirtualSize` ของ sections เหล่านี้บอกว่าข้อมูล (global variables, constants, strings) ถูกเก็บไว้ที่ใดใน memory Disassembler/decompiler จะใช้ข้อมูลนี้ในการอ้างอิงตัวแปรหรือสตริงที่โค้ดใช้งาน
    *   **Strings:** สตริงที่พบใน `.rdata` หรือ data sections อื่นๆ มักจะให้เบาะแสสำคัญเกี่ยวกับฟังก์ชันการทำงาน, error messages, หรือ configuration

5.  **การจัดการทรัพยากร (Resources):**
    *   **Resource Table:** หากโปรแกรมใช้ทรัพยากร (เช่น dialog templates, string tables, custom data) นัก RE สามารถใช้เครื่องมือ PE viewer หรือ resource editor ในการ extract และตรวจสอบทรัพยากรเหล่านั้น ซึ่งอาจมีข้อมูล config, UI layout, หรือแม้แต่ payloads ที่ซ่อนอยู่

6.  **การจัดการ Relocations:**
    *   **Base Relocation Table (`.reloc` section):** ถึงแม้ disassembler ส่วนใหญ่จะจัดการเรื่อง `ImageBase` และ RVA/VA โดยอัตโนมัติ แต่การเข้าใจว่ามี relocation entries อยู่ที่ใดบ้าง อาจช่วยในการทำความเข้าใจว่าส่วนใดของโค้ด/ข้อมูลที่มี absolute addresses ซึ่งอาจเป็นเป้าหมายของการ patch หรือการวิเคราะห์ memory dump ที่ image ถูกโหลดที่ base อื่น

7.  **การทำความเข้าใจโครงสร้างเฉพาะ (TLS, Load Config, .NET):**
    *   **TLS Table:** ถ้ามี TLS callbacks, OEP ที่แท้จริงอาจจะอยู่ใน callback นั้น ไม่ใช่ `AddressOfEntryPoint` ปกติ นัก RE ต้องตรวจสอบส่วนนี้
    *   **Load Configuration Table:** อาจมีข้อมูลเกี่ยวกับ security mitigations (SEH, GS, CFG) ซึ่งนัก RE ต้องทราบเพื่อทำความเข้าใจว่าโปรแกรมมีการป้องกันตัวเองอย่างไร
    *   **.NET Header (CLR Header):** ถ้าเป็น .NET PE, การ RE จะเปลี่ยนไปใช้เครื่องมือเฉพาะสำหรับ .NET (เช่น dnSpy, ILSpy) เพื่อ decompile MSIL (Microsoft Intermediate Language) code กลับเป็น C# หรือ VB.NET PE header จะชี้ไปยัง .NET metadata ที่จำเป็น

8.  **การรับมือกับ Packers/Obfuscators:**
    *   ความรู้เรื่อง PE format ช่วยในการระบุว่าไฟล์น่าจะถูก pack หรือ obfuscate (จากลักษณะของ entry point, imports, section entropy, etc.)
    *   ในระหว่างการ manual unpacking นัก RE จะต้องใช้ความรู้เรื่อง PE structure ในการ dump memory, หา OEP, และ rebuild IAT/relocations เพื่อให้ได้ original PE ที่สามารถ RE ต่อได้

**สรุปสำหรับ RE:** PE format เป็นจุดเริ่มต้นที่ขาดไม่ได้ มันให้โครงสร้างและ metadata ที่จำเป็นในการ "นำทาง" disassembler และ decompiler และช่วยให้นัก RE สามารถเริ่มทำความเข้าใจโปรแกรมที่ไม่รู้จักได้

## 18.2 Vulnerability Analysis (การวิเคราะห์ช่องโหว่) และ PE Format

**Vulnerability Analysis** คือกระบวนการค้นหา, ระบุ, และประเมินจุดอ่อน (ช่องโหว่) ในซอฟต์แวร์หรือระบบ ที่อาจถูกผู้ไม่หวังดีใช้ในการโจมตี (exploit) เพื่อให้ได้สิทธิ์เข้าถึงโดยไม่ได้รับอนุญาต, ขโมยข้อมูล, หรือทำให้ระบบไม่สามารถให้บริการได้ (Denial of Service)

ความรู้เรื่อง PE format มีบทบาทสำคัญในการวิเคราะห์ช่องโหว่ที่เกี่ยวข้องกับการจัดการ PE file โดยตรง หรือช่องโหว่ในโปรแกรมที่ทำงานกับ PE files:

1.  **ช่องโหว่ใน PE Parsers/Loaders:**
    *   โปรแกรมจำนวนมาก (เช่น Antivirus, security tools, OS loader เอง, unpackers) จำเป็นต้อง parse โครงสร้าง PE file
    *   หาก PE parser ไม่ได้ตรวจสอบความถูกต้องของค่าต่างๆ ใน PE header (เช่น `SizeOfOptionalHeader`, `NumberOfSections`, `SizeOfHeaders`, `PointerToRawData`, `VirtualAddress`, `SizeOfBlock` ใน relocation) อย่างรอบคอบ อาจเกิดช่องโหว่ได้ เช่น:
        *   **Integer Overflows/Underflows:** ในการคำนวณขนาดหรือ offset
        *   **Buffer Overflows (Stack/Heap):** หาก parser จัดสรร buffer โดยอิงตามค่าขนาดจาก PE header ที่ผู้โจมตีควบคุมได้ (เช่น `NumberOfSections` ที่ใหญ่มาก) แล้วพยายาม copy ข้อมูลเข้ามาโดยไม่ตรวจสอบขอบเขต
        *   **Out-of-Bounds Reads/Writes:** หาก offset หรือ RVA ที่อ่านจาก PE header ชี้ออกนอกขอบเขตที่ถูกต้องของไฟล์หรือ memory region
    *   **Fuzzing:** การใช้เทคนิค fuzzing (การป้อนข้อมูล input ที่ผิดปกติหรือสุ่มๆ เข้าไปใน PE parser) เพื่อหา crash หรือพฤติกรรมที่ไม่คาดคิด เป็นวิธีหนึ่งในการค้นหาช่องโหว่เหล่านี้ นักวิจัยช่องโหว่จะสร้าง PE files ที่ "malformed" (มีโครงสร้างผิดเพี้ยน) โดยตั้งใจเพื่อทดสอบ parser
    *   **ความรู้เรื่อง PE format:** จำเป็นอย่างยิ่งในการสร้าง test cases ที่ malformed อย่างมีความหมาย และในการทำความเข้าใจ root cause ของ crash เมื่อ fuzzer พบ

2.  **ช่องโหว่ที่เกี่ยวข้องกับ Memory Layout ที่ PE กำหนด:**
    *   **Understanding ASLR และ DEP:** `DllCharacteristics` (เช่น `DYNAMIC_BASE`, `NX_COMPAT`) และ Load Configuration Table บอกว่า image นั้นรองรับ ASLR และ DEP หรือไม่ หากไม่รองรับ จะเป็นเป้าหมายที่ง่ายกว่าสำหรับการ exploit ช่องโหว่ memory corruption
    *   **Relocation Table (`.reloc`):** หาก image ไม่มี relocation table มันจะไม่สามารถถูกสุ่ม `ImageBase` โดย ASLR ได้อย่างมีประสิทธิภาพ
    *   **Section Permissions:** ช่องโหว่ที่ทำให้สามารถเขียนไปยัง memory region ที่ execute ได้ (W+X) หรือ execute โค้ดจาก data region เป็นสิ่งที่นัก exploit มองหา ความรู้เรื่อง section characteristics จาก PE header ช่วยในการระบุ memory regions เหล่านี้
    *   **ImageBase และ SizeOfImage:** กำหนดขอบเขตของ PE image ใน memory ซึ่งสำคัญต่อการคำนวณ offset ในการทำ exploit

3.  **ช่องโหว่ในกระบวนการ Dynamic Linking (Imports/Exports):**
    *   **DLL Hijacking:** อาศัยความเข้าใจใน DLL Search Order และการที่โปรแกรมไม่ได้ระบุ full path ของ DLL ที่จะโหลด (หรือโหลด DLL จาก current directory ที่ผู้โจมตีควบคุมได้)
    *   **IAT Hooking / EAT Hooking (โดยผู้ไม่หวังดี):** ถ้าโปรแกรมมีช่องโหว่ที่ทำให้ผู้โจมตีสามารถเขียนไปยัง IAT หรือ EAT ของมันได้ (ซึ่งยากมากถ้ามี memory protection ที่ดี) ก็อาจจะ redirect API calls ได้
    *   **Forwarder Abuse:** การสร้าง PE file (เช่น DLL ปลอม) ที่มี forwarder ชี้ไปยังโค้ดอันตราย

4.  **ช่องโหว่ที่เกี่ยวข้องกับ Resources:**
    *   บางโปรแกรมอาจ parse resource data (เช่น custom binary data ใน `RT_RCDATA`) อย่างไม่ปลอดภัย ทำให้เกิด buffer overflow หรือช่องโหว่อื่นๆ ถ้า resource นั้นถูกสร้างขึ้นมาอย่างประสงค์ร้าย

5.  **Exploit Development:**
    *   เมื่อพบช่องโหว่ (เช่น buffer overflow) นักพัฒนา exploit จะต้อง:
        *   **ควบคุม Instruction Pointer (EIP/RIP):** ให้ชี้ไปยัง shellcode
        *   **วาง Shellcode:** หาตำแหน่งใน memory ที่สามารถเขียน shellcode ลงไปได้ และ execute ได้ (อาจจะต้อง bypass DEP)
        *   **Bypassing ASLR:** หาทาง leak addresses ของ loaded modules (เช่น `ImageBase` ของ `kernel32.dll`) เพื่อคำนวณที่อยู่ของ API ที่ต้องการใช้ (เช่น `VirtualProtect` เพื่อเปลี่ยน memory permission) หรือใช้ ROP (Return-Oriented Programming)
    *   **ความรู้เรื่อง PE format:** ช่วยในการหา RVA ของ API ที่ต้องการ (จาก IAT/EAT), หา RVA ของ ROP gadgets, และทำความเข้าใจ memory layout ของ target process

**ตัวอย่างสถานการณ์:**
*   นักวิจัยพบว่า Antivirus ตัวหนึ่ง crash เมื่อ scan PE file ที่มี `NumberOfSections` เป็นค่าที่ใหญ่มาก และ `PointerToRawData` ของ section header สุดท้ายชี้ไปยัง offset ที่ทำให้เกิดการอ่านนอกไฟล์ (out-of-bounds read) นี่คือช่องโหว่ใน PE parser ของ Antivirus นั้น
*   โปรแกรมหนึ่งโหลด DLL โดยใช้ชื่อ "version.dll" โดยไม่ได้ระบุ full path หากผู้โจมตีสามารถวาง "version.dll" ที่เป็นอันตรายไว้ใน directory เดียวกับโปรแกรมนั้นได้ ก็จะเกิด DLL Hijacking

## 18.3 เครื่องมือที่ใช้ใน RE และ Vulnerability Analysis (นอกเหนือจาก PE Viewers)

1.  **Disassemblers/Decompilers:**
    *   **IDA Pro:** มาตรฐานอุตสาหกรรม มี decompiler (Hex-Rays) ที่ทรงพลัง
    *   **Ghidra:** พัฒนาโดย NSA, open source, มี decompiler ในตัว
    *   **Radare2/Cutter:** Open source, command-line (Radare2) และ GUI (Cutter)
    *   **Binary Ninja:** Commercial, มี API ที่ดีสำหรับการเขียน script

2.  **Debuggers:**
    *   **x64dbg/x32dbg:** Open source debugger สำหรับ Windows (user-mode)
    *   **WinDbg:** Powerful debugger จาก Microsoft (user-mode และ kernel-mode)
    *   **OllyDbg (เก่าแต่ยังใช้กัน):** User-mode debugger สำหรับ 32-bit
    *   IDA Pro, Ghidra ก็มี debugger ในตัว

3.  **Fuzzers:**
    *   **AFL (American Fuzzy Lop) และ variants (AFL++, WinAFL):** เครื่องมือ fuzzing ที่ได้รับความนิยม
    *   **libFuzzer:** In-process fuzzer ที่ใช้กับ Clang
    *   **Boofuzz:** Network protocol fuzzer

4.  **Symbolic/Concolic Execution Engines:**
    *   **Angr, Triton, Manticore:** ช่วยในการวิเคราะห์ path ในโปรแกรม และหา input ที่จะทำให้ไปถึง path นั้นๆ (มีประโยชน์ในการหา exploit)

5.  **Scripting Languages (Python):**
    *   ไลบรารีเช่น `pefile`, `LIEF` ช่วยในการ parse และ manipulate PE files ด้วย Python ซึ่งมีประโยชน์ในการ automate การวิเคราะห์ หรือสร้าง PE ที่ malformed

## 18.4 สรุป

ความรู้เรื่อง PE format เป็นทักษะพื้นฐานที่สำคัญอย่างยิ่งสำหรับนัก Reverse Engineer และนักวิเคราะห์ช่องโหว่บนแพลตฟอร์ม Windows มันให้บริบทและโครงสร้างที่จำเป็นในการเริ่มแกะโค้ด, ทำความเข้าใจการทำงานของโปรแกรม, และระบุจุดอ่อนที่อาจถูกโจมตีได้

ไม่ว่าจะเป็นการหา OEP, การตามรอย API calls ผ่าน IAT, การวิเคราะห์ exports ของ DLL, การตรวจสอบ section permissions, หรือการสร้าง PE ที่ malformed เพื่อทดสอบ parser ทั้งหมดนี้ล้วนต้องอาศัยความเข้าใจที่ลึกซึ้งในรายละเอียดของ PE file format

ในบทต่อไป เราจะมาดูกันว่า PE format มีบทบาทอย่างไรในงาน **Digital Forensics และ Incident Response (DFIR)**
