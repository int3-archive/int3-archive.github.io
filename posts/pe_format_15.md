---
date: 2025-01-15
title: PE Format บทที่ 15 - การเชื่อมโยง (Linking) และการโหลด Dynamic-Link Libraries (DLLs)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: แนวคิดของการเชื่อมโยง (Linking) โดยเฉพาะอย่างยิ่ง Dynamic Linking และบทบาทสำคัญของ Dynamic-Link Libraries (DLLs) ในระบบนิเวศของ Windows
---

# บทที่ 15 - การเชื่อมโยง (Linking) และการโหลด Dynamic-Link Libraries (DLLs)

ในบทที่แล้ว เราได้เห็นภาพรวมของกระบวนการโหลด PE file ซึ่งรวมถึงการจัดการ imports และการโหลด DLLs ที่จำเป็น ในบทนี้ เราจะมาเจาะลึกแนวคิดของการเชื่อมโยง (Linking) โดยเฉพาะอย่างยิ่ง **Dynamic Linking** และบทบาทสำคัญของ Dynamic-Link Libraries (DLLs) ในระบบนิเวศของ Windows

DLLs เป็นส่วนประกอบพื้นฐานของ Windows และแอปพลิเคชันส่วนใหญ่ การทำความเข้าใจว่า DLLs คืออะไร, ทำงานอย่างไร, และถูกโหลดและเชื่อมโยงกับโปรแกรมอื่นอย่างไร เป็นสิ่งจำเป็นสำหรับการพัฒนาซอฟต์แวร์, การแก้ไขปัญหา, และที่สำคัญสำหรับรายวิชานี้ คือการวิเคราะห์พฤติกรรมของมัลแวร์ที่มักจะมาในรูปแบบของ DLL หรือใช้ DLLs ในการทำงาน

## 15.1 การเชื่อมโยง (Linking) คืออะไร?

ในกระบวนการพัฒนาซอฟต์แวร์ หลังจากที่ source code ถูกคอมไพล์ (compile) เป็น object code (.obj files) แล้ว ขั้นตอนต่อไปคือ **การเชื่อมโยง (Linking)** ซึ่งทำโดยโปรแกรมที่เรียกว่า **Linker**

**Object Code (.obj files):**
*   แต่ละ `.obj` ไฟล์มักจะแทน source file หนึ่งไฟล์ที่ถูกคอมไพล์
*   ประกอบด้วย machine code, data, และ "สัญลักษณ์" (symbols) ที่ยังไม่ถูก resolve เช่น:
    *   **External Symbols:** การอ้างอิงไปยังฟังก์ชันหรือตัวแปรที่ถูกกำหนดไว้ใน `.obj` ไฟล์อื่น หรือในไลบรารี
    *   **Public Symbols (Exports):** ฟังก์ชันหรือตัวแปรที่ `.obj` ไฟล์นี้ทำให้พร้อมใช้งานสำหรับ `.obj` ไฟล์อื่น
*   ยังไม่สามารถทำงานได้โดยตรง

**หน้าที่ของ Linker:**
1.  **รวม Object Files:** นำ `.obj` ไฟล์หลายๆ ไฟล์ที่ประกอบกันเป็นโปรแกรมหรือไลบรารีมารวมกัน
2.  **Resolve External Symbols:** ค้นหาคำจำกัดความ (definition) ของ external symbols ที่แต่ละ `.obj` ไฟล์อ้างอิง โดยดูจาก `.obj` ไฟล์อื่นในโปรเจกต์ หรือจาก **ไลบรารี (libraries)**
3.  **จัดสรรหน่วยความจำ:** กำหนดตำแหน่ง (Relative Virtual Addresses - RVAs) ให้กับโค้ดและข้อมูลจาก `.obj` ไฟล์ต่างๆ ภายใน PE image สุดท้าย
4.  **สร้าง Executable Image:** สร้าง PE file (.EXE หรือ .DLL) ที่สมบูรณ์ พร้อมด้วย PE headers, section table, และ sections ที่มีโค้ดและข้อมูลที่ถูกจัดเรียงแล้ว

**ประเภทของการเชื่อมโยง:**

1.  **Static Linking:**
    *   **การทำงาน:** โค้ดจากไลบรารี (static libraries, .LIB files) ที่โปรแกรมเรียกใช้ จะถูก **คัดลอก** เข้าไปรวมเป็นส่วนหนึ่งของ PE file (.EXE) โดยตรง ณ เวลาที่ linker ทำงาน
    *   **ผลลัพธ์:** .EXE ไฟล์จะมีขนาดใหญ่ขึ้น เพราะมีสำเนาของโค้ดไลบรารีอยู่ภายในตัวเอง
    *   **ข้อดี:**
        *   โปรแกรมมีความสมบูรณ์ในตัวเอง ไม่ต้องพึ่งพา DLL ภายนอก (สำหรับโค้ดที่ static link)
        *   อาจจะโหลดเร็วกว่าเล็กน้อย (ในบางกรณี) เพราะโค้ดอยู่ใน image เดียวกัน
    *   **ข้อเสีย:**
        *   ขนาดไฟล์ .EXE ใหญ่
        *   หากไลบรารีมีการอัปเดต (เช่น แก้ไข bug, เพิ่ม security patch) โปรแกรมจะต้องถูก re-link และ re-compile ใหม่ทั้งหมดเพื่อให้ได้โค้ดที่อัปเดต
        *   สิ้นเปลืองหน่วยความจำ หากหลายๆ โปรแกรม static link กับไลบรารีเดียวกัน จะมีสำเนาของโค้ดไลบรารีนั้นใน memory ของแต่ละ process

2.  **Dynamic Linking:**
    *   **การทำงาน:** โค้ดจากไลบรารี (dynamic-link libraries, .DLL files) **ไม่** ถูกคัดลอกเข้าไปใน .EXE ไฟล์ ณ เวลา link time แต่ linker จะบันทึกข้อมูลไว้ใน Import Table ของ .EXE ว่ามันต้องการใช้ฟังก์ชันอะไรบ้างจาก DLL ใด
    *   ณ **Runtime** (เมื่อโปรแกรม .EXE ถูกโหลดและทำงาน) Windows Loader จะ:
        1.  โหลด DLLs ที่จำเป็นเข้าสู่ address space ของ process (ถ้ายังไม่ได้โหลด)
        2.  ทำการ "เชื่อมโยง" (resolve) การเรียกฟังก์ชันใน .EXE ไปยังที่อยู่จริงของฟังก์ชันใน DLLs ที่โหลดแล้ว (โดยการแก้ไข Import Address Table - IAT)
    *   **ผลลัพธ์:** .EXE ไฟล์มีขนาดเล็กกว่า เพราะมีเพียงข้อมูลการ import
    *   **ข้อดี:**
        *   **Code Sharing:** DLL หนึ่งไฟล์สามารถถูก map เข้าไปใน address space ของหลายๆ process ได้ แต่โค้ดของ DLL นั้น (ส่วนที่เป็น read-only, execute-only เช่น .text section) จะมีเพียง **สำเนาเดียวใน physical memory** (OS ใช้ copy-on-write สำหรับ data sections ที่ writable) ช่วยประหยัด RAM
        *   **Modularity:** โปรแกรมถูกแบ่งเป็นส่วนๆ ทำให้พัฒนาและทดสอบง่ายขึ้น
        *   **Easy Updates:** หาก DLL มีการอัปเดต (โดยที่ API interface ไม่เปลี่ยนแปลง) โปรแกรมที่ใช้ DLL นั้นสามารถได้ประโยชน์จากการอัปเดตโดยไม่ต้อง re-compile โปรแกรมหลัก (แค่เปลี่ยนไฟล์ DLL)
        *   **Reduced Disk Space:** ลดการซ้ำซ้อนของโค้ดบนดิสก์
    *   **ข้อเสีย:**
        *   **Dependency Management:** โปรแกรมต้องพึ่งพาการมีอยู่ของ DLLs ที่ถูกต้องในระบบ (ปัญ "DLL Hell" ในอดีต คือการมี DLL หลายเวอร์ชันที่เข้ากันไม่ได้)
        *   **Slightly Slower Load Time (Potentially):** มี overhead เล็กน้อยในการโหลด DLLs และ resolve imports ตอน runtime
        *   **Security Risks:** DLL Hijacking (การหลอกให้โปรแกรมโหลด DLL ที่เป็นอันตรายแทน DLL ที่ถูกต้อง)

**Windows ใช้ Dynamic Linking เป็นหลัก** สำหรับ API ของระบบ (Kernel32, User32, Gdi32, Advapi32, ฯลฯ) และไลบรารีส่วนใหญ่

## 15.2 Dynamic-Link Libraries (DLLs) คืออะไร?

DLL คือ PE file ชนิดหนึ่ง (มีโครงสร้าง PE header เหมือน .EXE) ที่บรรจุโค้ดและ/หรือข้อมูลที่สามารถถูกเรียกใช้งานร่วมกันโดยหลายโปรแกรม
*   **ไม่สามารถรันได้โดยตรง:** ผู้ใช้ไม่สามารถดับเบิลคลิกไฟล์ .DLL เพื่อรันมันเป็นโปรแกรมเอกเทศได้ (ยกเว้น DLL นั้นถูกออกแบบมาให้รันด้วย `rundll32.exe` หรือเป็น COM server)
*   **ต้องถูกโหลดโดย Process:** DLL จะทำงานได้ก็ต่อเมื่อถูกโหลดเข้าสู่ address space ของ process ที่เป็น .EXE (หรือ process อื่นที่โหลดมัน)
*   **มี Entry Point ของตัวเอง (`DllMain`):** DLL สามารถมีฟังก์ชัน entry point ที่เรียกว่า `DllMain` (ถ้ามี) ซึ่งจะถูกเรียกโดย loader เมื่อ DLL ถูกโหลดเข้า process (`DLL_PROCESS_ATTACH`), ถูก unload ออกจาก process (`DLL_PROCESS_DETACH`), หรือเมื่อ thread ใหม่ถูกสร้าง (`DLL_THREAD_ATTACH`) หรือสิ้นสุด (`DLL_THREAD_DETACH`) ใน process นั้น
*   **Export Functions/Data:** DLL ให้บริการฟังก์ชันหรือข้อมูลแก่โปรแกรมอื่นผ่านทาง **Export Table** (EAT)
*   **Import Functions/Data:** DLL ก็สามารถ import ฟังก์ชันจาก DLL อื่นได้เช่นกัน (รวมถึง system DLLs) ผ่านทาง **Import Table** (IAT) ของตัวเอง

**ตัวอย่างการใช้งาน DLLs:**
*   **System APIs:** `Kernel32.dll` ให้บริการฟังก์ชันพื้นฐานของ OS เช่น การจัดการ process, memory, files `User32.dll` ให้บริการฟังก์ชันเกี่ยวกับ UI เช่น การสร้าง windows, messages `Gdi32.dll` ให้บริการฟังก์ชันเกี่ยวกับการวาดภาพ
*   **Runtime Libraries:** C Runtime Library (CRT) เช่น `msvcrt.dll` หรือ `ucrtbase.dll` ให้บริการฟังก์ชันมาตรฐานของภาษา C (เช่น `printf`, `malloc`, `strcpy`)
*   **Device Drivers (.SYS files):** เป็น DLL ชนิดพิเศษที่ทำงานใน kernel mode เพื่อควบคุมฮาร์ดแวร์
*   **COM Components (.DLL, .OCX):** ใช้ Component Object Model (COM) เพื่อให้บริการ object-oriented แก่แอปพลิเคชันอื่น
*   **Application-Specific DLLs:** โปรแกรมขนาดใหญ่มักจะแบ่งฟังก์ชันการทำงานออกเป็น DLLs หลายๆ ตัวเพื่อ modularity

## 15.3 กระบวนการโหลดและเชื่อมโยง DLL

เมื่อโปรแกรม .EXE (หรือ DLL อื่น) ต้องการใช้ฟังก์ชันจาก DLL ที่ระบุไว้ใน Import Table ของมัน Windows Loader จะดำเนินการดังนี้ (ส่วนหนึ่งทบทวนจากบทที่ 14):

1.  **ค้นหา DLL:**
    *   Loader จะค้นหาไฟล์ DLL นั้นตามลำดับที่กำหนดไว้ (DLL Search Order) ซึ่งโดยทั่วไปคือ:
        1.  Directory ที่ .EXE หลักถูกโหลด
        2.  System directory (`C:\Windows\System32`)
        3.  16-bit system directory (`C:\Windows\System`) - (สำหรับ backward compatibility)
        4.  Windows directory (`C:\Windows`)
        5.  Current directory (ถ้าไม่ได้ถูกป้องกันด้วย SafeDllSearchMode หรือ `SetDllDirectory`)
        6.  Directories ที่ระบุใน `PATH` environment variable
    *   **KnownDLLs:** OS มี list ของ system DLLs ที่รู้จัก (เก็บใน Registry) ซึ่งจะถูกโหลดจาก system directory โดยตรงเพื่อความปลอดภัยและประสิทธิภาพ
    *   **Manifest Redirection (SxS):** Application manifest สามารถระบุเวอร์ชันเฉพาะของ DLL ที่ต้องการใช้ (Side-by-Side assemblies) ซึ่ง loader จะค้นหาใน WinSxS cache

2.  **Map DLL เข้าสู่ Memory:**
    *   ถ้า DLL ถูกพบและยังไม่ได้ถูกโหลดเข้าสู่ process นั้น Loader จะ map PE image ของ DLL นั้นเข้าสู่ address space ของ process (ทำตามขั้นตอนการโหลด PE image ที่อธิบายในบทที่ 14: ตรวจสอบ headers, จัดการ `ImageBase` และ relocation, map sections, ตั้ง memory protection)

3.  **เรียก `DllMain` (ถ้ามี) ด้วย `DLL_PROCESS_ATTACH`:**
    *   Loader เรียก `DllMain` ของ DLL ที่เพิ่งโหลด เพื่อให้ DLL ทำการ initialize ตัวเอง
    *   ถ้า `DllMain` คืนค่า `FALSE` การโหลด DLL จะล้มเหลว

4.  **Resolve Imports ที่ชี้ไปยัง DLL นี้:**
    *   สำหรับ image เดิม (ที่กำลัง import จาก DLL นี้) loader จะแก้ไข IAT entries ที่เกี่ยวข้อง ให้ชี้ไปยังที่อยู่จริงของฟังก์ชันใน DLL ที่เพิ่งโหลดนี้

5.  **ถ้า DLL ที่โหลดใหม่นี้มี Imports ของตัวเอง:**
    *   Loader จะประมวลผล Import Table ของ DLL ใหม่นี้แบบซ้ำ (recursively) เพื่อโหลด dependencies ทั้งหมดของมัน

**การ Unload DLL:**
*   เมื่อ DLL ไม่ถูกใช้งานโดย process อีกต่อไป (เช่น โปรแกรมจบการทำงาน หรือมีการเรียก `FreeLibrary` API และ reference count ของ DLL เป็น 0)
*   Loader จะเรียก `DllMain` ของ DLL นั้นด้วย `fdwReason` เป็น `DLL_PROCESS_DETACH` เพื่อให้ DLL ทำการ cleanup
*   จากนั้น memory ที่ DLL นั้นใช้จะถูก unmap ออกจาก address space ของ process

## 15.4 ประเภทของการโหลด DLL

1.  **Load-Time Dynamic Linking (Implicit Linking):**
    *   **การทำงาน:** นี่คือวิธีที่พบบ่อยที่สุด DLLs ที่ระบุใน Import Table ของ .EXE จะถูกโหลดโดยอัตโนมัติโดย Windows Loader เมื่อ .EXE นั้นเริ่มทำงาน
    *   **การใช้งาน:** โปรแกรมเรียกฟังก์ชันจาก DLL เหมือนกับว่าเป็นฟังก์ชันภายในโปรแกรมเอง (linker ได้สร้าง stub หรือ import descriptor ไว้ให้แล้ว)
    *   **ข้อดี:** ง่ายต่อการใช้งานสำหรับโปรแกรมเมอร์
    *   **ข้อเสีย:** ถ้า DLL ใด DLL หนึ่งที่จำเป็นหายไปหรือไม่ถูกต้อง โปรแกรม .EXE ทั้งหมดจะไม่สามารถเริ่มทำงานได้เลย

2.  **Run-Time Dynamic Linking (Explicit Linking):**
    *   **การทำงาน:** โปรแกรมสามารถโหลดและ unload DLLs ได้เองตามต้องการในระหว่างที่มันทำงาน โดยใช้ Windows API:
        *   `LoadLibrary` หรือ `LoadLibraryEx`: โหลด DLL เข้าสู่ memory และคืนค่า `HMODULE` (ซึ่งก็คือ `ImageBase` ของ DLL ที่โหลด) ถ้าสำเร็จ
        *   `GetProcAddress`: ค้นหาที่อยู่ (VA) ของฟังก์ชันที่ export โดย DLL นั้น (โดยใช้ชื่อฟังก์ชันหรือ ordinal) จาก `HMODULE` ที่ได้จาก `LoadLibrary`
        *   `FreeLibrary`: ลด reference count ของ DLL ถ้าเป็น 0 จะ unload DLL ออกจาก memory
    *   **การใช้งาน:** โปรแกรมต้องเก็บ function pointer ที่ได้จาก `GetProcAddress` แล้วเรียกฟังก์ชันผ่าน pointer นั้น
    *   **ข้อดี:**
        *   โปรแกรมสามารถเริ่มทำงานได้แม้ DLL บางตัวจะไม่มีอยู่ (สามารถจัดการ error ได้เอง)
        *   สามารถเลือกโหลด DLL ที่ต้องการตามเงื่อนไข หรือโหลด plugin ได้
        *   ลด memory footprint เริ่มต้น ถ้า DLL ไม่ได้ถูกใช้ทันที
    *   **ข้อเสีย:** ซับซ้อนกว่าในการเขียนโค้ด

## 15.5 Cybersecurity Relevance ของ DLLs และ Linking

DLLs เป็นเป้าหมายและเครื่องมือที่มัลแวร์ใช้บ่อยมาก:

1.  **Malware ในรูปแบบ DLL:**
    *   มัลแวร์จำนวนมาก (เช่น RATs, spyware, banking trojans) ถูกสร้างเป็น DLL เพื่อให้สามารถถูก inject เข้าไปใน process อื่นที่ถูกกฎหมาย (เช่น `explorer.exe`, `svchost.exe`, web browsers)
    *   การรันโค้ดใน context ของ process อื่นช่วยให้มัลแวร์หลีกเลี่ยงการตรวจจับ, bypass firewall, หรือเข้าถึงข้อมูลของ process นั้นได้
    *   DLL malware มักจะ export ฟังก์ชันบางอย่างที่ loader (เช่น `rundll32.exe` หรือ custom loader) เรียกเพื่อเริ่มการทำงาน หรืออาจจะทำงานผ่าน `DllMain`

2.  **DLL Injection:**
    *   เป็นเทคนิคที่มัลแวร์ใช้ในการบังคับให้ process อื่นโหลดและรัน DLL ที่เป็นอันตราย มีหลายวิธี เช่น:
        *   **CreateRemoteThread + LoadLibrary:** มัลแวร์เขียน path ของ DLL ตัวเองลงใน memory ของ target process แล้วสร้าง remote thread ใน target process ให้เรียก `LoadLibrary` ด้วย path นั้น
        *   **SetWindowsHookEx:** ตั้งค่า global hook ที่จะโหลด DLL เข้าไปในทุก GUI process
        *   **Registry (AppInit_DLLs, AppCertDlls):** แก้ไข Registry key เพื่อให้ OS โหลด DLL ที่ระบุเข้าทุก user-mode process (หรือ process ที่สร้าง UI)
        *   **Reflective DLL Injection:** โหลด DLL จาก memory โดยตรง ไม่ต้องมีไฟล์บนดิสก์
    *   เมื่อ DLL ถูก inject เข้าไปแล้ว มันสามารถทำงานใน context ของ target process ได้

3.  **DLL Hijacking (DLL Search Order Hijacking):**
    *   มัลแวร์วาง DLL ที่มีชื่อเดียวกับ DLL ที่ถูกกฎหมาย (แต่เป็นเวอร์ชันอันตราย) ไว้ในตำแหน่งที่ loader จะค้นเจอก่อน DLL ที่ถูกต้อง (เช่น ใน directory เดียวกับ .EXE)
    *   เมื่อ .EXE โหลด DLL นั้น มันจะได้ DLL ที่เป็นอันตรายแทน มัลแวร์ DLL อาจจะ forward การเรียกไปยัง DLL ที่ถูกต้องหลังจากทำงานอันตรายของตัวเองเสร็จแล้ว (proxying) เพื่อไม่ให้โปรแกรม crash

4.  **API Hooking (ผ่าน IAT, EAT, หรือ Inline Hooking):**
    *   ดังที่กล่าวในบทที่ 9 มัลแวร์สามารถ hook API calls เพื่อดักข้อมูล, bypass security, หรือซ่อนพฤติกรรม

5.  **Packing และ Dynamic API Resolution:**
    *   Packers มักจะซ่อน Import Table ของ original code และทำการ resolve API ที่ต้องการใช้ใน runtime (ผ่าน `LoadLibrary` และ `GetProcAddress`) เพื่อทำให้ static analysis ยากขึ้น

6.  **การวิเคราะห์ DLL Malware:**
    *   ต้องระบุว่า DLL ถูกโหลดและทำงานอย่างไร (เช่น `DllMain` ถูกเรียกด้วย reason อะไร, ฟังก์ชัน export ใดถูกเรียก)
    *   อาจจะต้องใช้ debugger ในการ attach เข้าไปใน process ที่ DLL นั้นถูก inject หรือใช้ host process เช่น `rundll32.exe` ในการรัน DLL เพื่อวิเคราะห์ (ถ้า DLL รองรับ)

## 15.6 สรุป

Dynamic Linking และ DLLs เป็นส่วนสำคัญของสถาปัตยกรรม Windows ที่ช่วยให้สามารถแชร์โค้ด, ลดขนาดโปรแกรม, และอัปเดตซอฟต์แวร์ได้ง่ายขึ้น กระบวนการโหลดและเชื่อมโยง DLL เกี่ยวข้องกับการค้นหา DLL, map เข้า memory, resolve imports, และเรียก `DllMain` ทั้งแบบ Load-Time (Implicit) และ Run-Time (Explicit) linking มีข้อดีข้อเสียและการใช้งานที่แตกต่างกัน

สำหรับ Cybersecurity, DLLs เป็นดาบสองคม พวกมันมีความจำเป็นต่อการทำงานของระบบ แต่ก็เป็นช่องทางและเครื่องมือยอดนิยมสำหรับมัลแวร์ในการซ่อนตัว, แพร่กระจาย, และโจมตีระบบ การทำความเข้าใจกลไกของ DLLs และวิธีการที่มัลแวร์ใช้ประโยชน์จากมันจึงเป็นทักษะที่ขาดไม่ได้สำหรับนักวิเคราะห์

นี่เป็นการสิ้นสุดของ **ส่วนที่ 3: PE Format และกระบวนการทำงานของระบบปฏิบัติการ**

ในส่วนถัดไป เราจะเข้าสู่ **ส่วนที่ 4: การประยุกต์ใช้ PE Format ในงาน Cybersecurity** โดยเริ่มจาก **บทที่ 16: การวิเคราะห์ PE File เพื่อตรวจจับมัลแวร์ (Static Analysis)**
