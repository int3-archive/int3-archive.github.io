---
date: 2025-01-14
title: PE Format บทที่ 14 - กระบวนการโหลด PE File เข้าสู่หน่วยความจำ (PE Loading Process)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: มาดูกันว่าเมื่อผู้ใช้ดับเบิลคลิกไฟล์ .EXE หรือเมื่อโปรแกรมหนึ่งเรียกโหลด DLL ระบบปฏิบัติการ Windows นำข้อมูลจาก PE file เหล่านั้นมาใช้ในการโหลดและเตรียมโปรแกรมให้พร้อมทำงานในหน่วยความจำได้อย่างไร
---

# บทที่ 14 - กระบวนการโหลด PE File เข้าสู่หน่วยความจำ (PE Loading Process)

หลังจากที่เราได้ศึกษารายละเอียดโครงสร้างของ PE file อย่างครบถ้วนแล้ว ในบทนี้เราจะมาดูกันว่าเมื่อผู้ใช้ดับเบิลคลิกไฟล์ .EXE หรือเมื่อโปรแกรมหนึ่งเรียกโหลด DLL ระบบปฏิบัติการ Windows (โดยเฉพาะ Windows Loader) นำข้อมูลจาก PE file เหล่านั้นมาใช้ในการโหลดและเตรียมโปรแกรมให้พร้อมทำงานในหน่วยความจำได้อย่างไร

กระบวนการโหลด PE file เป็นขั้นตอนที่ซับซ้อนและมีความสำคัญอย่างยิ่ง เพราะเป็นการ "ปลุกชีวิต" ให้กับข้อมูลที่เก็บอยู่ในไฟล์ PE ทำให้มันกลายเป็น process ที่ทำงานได้ในระบบ การทำความเข้าใจกระบวนการนี้ช่วยให้เห็นภาพว่าส่วนต่างๆ ของ PE header และ sections ถูกนำมาใช้งานจริงอย่างไร และยังเป็นพื้นฐานสำคัญในการทำความเข้าใจเทคนิคต่างๆ ใน Cybersecurity เช่น process injection, hollowing, หรือการทำงานของ packers

**ผู้รับผิดชอบหลัก: Windows Loader**

กระบวนการโหลดส่วนใหญ่ดำเนินการโดย **Windows Loader** ซึ่งเป็นส่วนหนึ่งของระบบปฏิบัติการ โดยมีคอมโพเนนต์หลักคือ `ntdll.dll` (ใน user mode) และส่วนของ Kernel (Executive subsystem) ที่เกี่ยวข้องกับการจัดการ process และ memory

## 14.1 การเริ่มต้นกระบวนการโหลด (กรณี Executable - .EXE)

เมื่อผู้ใช้สั่งรันโปรแกรม .EXE (เช่น ผ่าน Explorer, Command Prompt, หรือ CreateProcess API):

1.  **Kernel สร้าง Process Object:**
    *   ระบบปฏิบัติการ (Kernel) จะสร้างโครงสร้างข้อมูลหลักสำหรับ process ใหม่ เช่น Process Environment Block (PEB), Kernel Process Block (EPROCESS), และจัดสรร Virtual Address Space (VAS) เริ่มต้นให้กับ process นั้น
    *   Thread แรกของ process (initial thread) ก็จะถูกสร้างขึ้นพร้อมกับ Kernel Thread Block (ETHREAD) และ User-mode stack

2.  **Kernel Map `ntdll.dll`:**
    *   `ntdll.dll` เป็น DLL พิเศษที่ถูก map เข้าไปใน address space ของทุกๆ user-mode process โดย Kernel `ntdll.dll` มีฟังก์ชันระดับต่ำจำนวนมากที่ใช้ติดต่อกับ Kernel และเป็นที่อยู่ของส่วนสำคัญของ Windows Loader ใน user mode
    *   Entry point ของ thread แรกจะถูกตั้งให้ชี้ไปยังฟังก์ชันเริ่มต้นใน `ntdll.dll` (เช่น `LdrInitializeThunk`)

3.  **Loader ใน `ntdll.dll` เริ่มทำงาน:**
    *   เมื่อ thread แรกเริ่มทำงานใน user mode มันจะเริ่มรันโค้ดใน `ntdll.dll` ส่วนนี้ของ loader จะรับผิดชอบในการโหลด PE image หลัก (.EXE) และ DLLs ที่มันพึ่งพา (dependencies)

## 14.2 ขั้นตอนการโหลด PE Image หลัก (.EXE หรือ DLL ที่ถูกโหลดครั้งแรก)

Windows Loader (ใน `ntdll.dll`) จะทำตามขั้นตอนต่อไปนี้เพื่อโหลด PE image หนึ่งๆ (ไม่ว่าจะเป็น .EXE หลัก หรือ DLL ที่ถูกโหลด):

1.  **เปิดไฟล์และตรวจสอบ DOS Header และ PE Signature:**
    *   Loader เปิดไฟล์ PE จากดิสก์
    *   อ่าน `IMAGE_DOS_HEADER` และตรวจสอบ `e_magic` ("MZ")
    *   อ่านค่า `e_lfanew` จาก DOS Header เพื่อหาตำแหน่งของ PE Signature
    *   อ่าน PE Signature และตรวจสอบว่าเป็น "PE\0\0" หรือไม่
    *   **สาเหตุ-เหตุผล:** เป็นการตรวจสอบเบื้องต้นว่าไฟล์เป็น PE file ที่ถูกต้องหรือไม่

2.  **อ่าน COFF File Header และ Optional Header:**
    *   Loader อ่าน `IMAGE_FILE_HEADER` (COFF Header) และ `IMAGE_OPTIONAL_HEADER` (Optional Header)
    *   ตรวจสอบความสอดคล้องของข้อมูล เช่น `Machine` type กับสถาปัตยกรรมปัจจุบัน, `Magic` number (PE32/PE32+), `SizeOfOptionalHeader`
    *   **สาเหตุ-เหตุผล:** เพื่อให้ได้ข้อมูลพื้นฐานและข้อมูลสำคัญสำหรับการโหลด image

3.  **ตรวจสอบ Preferred Image Base (`ImageBase`):**
    *   Loader อ่านค่า `ImageBase` จาก Optional Header ซึ่งเป็นตำแหน่ง VA ที่ image ต้องการจะถูกโหลด
    *   ตรวจสอบว่า address range ตั้งแต่ `ImageBase` ถึง `ImageBase + SizeOfImage` นั้นว่างอยู่ใน Virtual Address Space ของ process หรือไม่
    *   **ถ้าว่าง:** Loader จะจอง (reserve) memory region ขนาด `SizeOfImage` ณ ตำแหน่ง `ImageBase` นั้น
    *   **ถ้าไม่ว่าง:**
        *   ถ้า image **ไม่มี** Base Relocation Table (Data Directory `IMAGE_DIRECTORY_ENTRY_BASERELOC` เป็น 0 หรือ `IMAGE_FILE_RELOCS_STRIPPED` flag ถูกตั้ง) **loader จะไม่สามารถโหลด image นั้นได้ และจะเกิดข้อผิดพลาด** (ยกเว้นเป็น PIC หรือกรณีพิเศษ)
        *   ถ้า image **มี** Base Relocation Table และรองรับการ relocate (flag `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` อาจมีผล) loader จะหาตำแหน่ง VA อื่นที่ว่างและมีขนาดเพียงพอ แล้วจอง memory region นั้นไว้ ตำแหน่งใหม่นี้จะกลายเป็น `ActualImageBase` ของ image
    *   **สาเหตุ-เหตุผล:** เพื่อหาตำแหน่งที่เหมาะสมในการ map image เข้าสู่ memory และเตรียมพร้อมสำหรับการ relocation ถ้าจำเป็น

4.  **Map Sections จากไฟล์เข้าสู่ Memory:**
    *   Loader อ่าน **Section Table** (array of `IMAGE_SECTION_HEADER`)
    *   สำหรับแต่ละ section header ในตาราง:
        a.  คำนวณตำแหน่ง VA ของ section ใน memory: `SectionVA = ActualImageBase + sectionHeader.VirtualAddress`
        b.  **Map หรือ Copy ข้อมูล Section:**
            *   ถ้า section มีข้อมูลบนดิสก์ (`sectionHeader.SizeOfRawData > 0`): Loader จะ map หรือ copy ข้อมูลขนาด `sectionHeader.SizeOfRawData` จากไฟล์ (ณ offset `sectionHeader.PointerToRawData`) ไปยัง `SectionVA` ใน memory
            *   ถ้า section ไม่มีข้อมูลบนดิสก์ (เช่น `.bss` section, `sectionHeader.SizeOfRawData == 0`): Loader จะแค่คอมมิต (commit) memory ขนาด `sectionHeader.VirtualSize` ณ `SectionVA` และ (โดยทั่วไป) initialize เป็นศูนย์
        c.  **ปรับขนาด Section ใน Memory:** ขนาดของ section ใน memory คือ `sectionHeader.VirtualSize` ถ้า `VirtualSize` ใหญ่กว่า `SizeOfRawData` ส่วนที่เกินมา (ที่ยังไม่ได้ map/copy) จะถูก zero-filled (เติมด้วยศูนย์)
        d.  **ตั้งค่า Memory Protection:** Loader ใช้ `Characteristics` flags ของ section (เช่น `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE`, `IMAGE_SCN_MEM_EXECUTE`) ในการตั้งค่า access permissions ที่เหมาะสมสำหรับ memory pages ที่ครอบคลุม section นั้นๆ (ผ่านทาง `VirtualProtect` หรือ API ระดับต่ำกว่า)
    *   **การจัดเรียง (Alignment):** ทั้ง `SectionVA` และ `PointerToRawData` จะต้องสอดคล้องกับ `SectionAlignment` และ `FileAlignment` ตามลำดับ
    *   **สาเหตุ-เหตุผล:** เพื่อนำโค้ดและข้อมูลจากไฟล์มาไว้ใน memory และกำหนดสิทธิ์การเข้าถึงที่ถูกต้อง

5.  **ประมวลผล Base Relocations (ถ้าจำเป็น):**
    *   ถ้า image ถูกโหลดที่ `ActualImageBase` ซึ่งแตกต่างจาก preferred `ImageBase` (คือ `Delta = ActualImageBase - PreferredImageBase != 0`):
        *   Loader จะประมวลผล **Base Relocation Table** (จาก Data Directory `IMAGE_DIRECTORY_ENTRY_BASERELOC` หรือ `.reloc` section) ตามที่อธิบายในบทที่ 12
        *   Loader จะวนผ่าน relocation blocks และ entries เพื่อ patch (แก้ไข) absolute addresses ทั้งหมดใน image โดยบวกด้วย `Delta`
    *   **สาเหตุ-เหตุผล:** เพื่อให้ hardcoded addresses ทั้งหมดในโค้ดและข้อมูลชี้ไปยังตำแหน่งที่ถูกต้องใน memory หลังจาก image ถูกย้าย

6.  **ประมวลผล Imports (Import Table):**
    *   Loader ค้นหา **Import Directory Table (IDT)** จาก Data Directory `IMAGE_DIRECTORY_ENTRY_IMPORT`
    *   สำหรับแต่ละ `IMAGE_IMPORT_DESCRIPTOR` ใน IDT (แต่ละ DLL ที่จะ import):
        a.  Loader อ่านชื่อ DLL จากฟิลด์ `Name`
        b.  **โหลด DLL ที่ import มา (ถ้ายังไม่ได้โหลด):**
            *   Loader จะเรียกตัวเองแบบซ้ำ (recursively) เพื่อโหลด DLL นั้น (ทำตามขั้นตอน 1-7 นี้สำหรับ DLL นั้น)
            *   ถ้า DLL นั้นมี dependencies (imports DLL อื่นอีกทอดหนึ่ง) ก็จะถูกโหลดแบบซ้ำไปเรื่อยๆ จนครบ (Depth-First Search)
            *   OS จะมีกลไกป้องกันการโหลด DLL เดิมซ้ำซ้อน (จะใช้ instance ที่โหลดแล้ว)
        c.  **Resolve Imported Functions:** เมื่อ DLL ที่ import มาถูกโหลดเข้า memory แล้ว loader จะวนผ่าน **Import Lookup Table (ILT/INT)** (ชี้โดย `OriginalFirstThunk`) และ **Import Address Table (IAT)** (ชี้โดย `FirstThunk`) ของ image ปัจจุบัน
        d.  สำหรับแต่ละฟังก์ชันที่ต้องการ import (ระบุโดยชื่อหรือ ordinal จาก ILT/INT):
            i.   Loader ค้นหา Virtual Address (VA) ของฟังก์ชันนั้นใน Export Table (EAT) ของ DLL ที่โหลดมา
            ii.  Loader **เขียน VA ที่ได้นี้ทับลงใน entry ที่สอดคล้องกันใน IAT** ของ image ปัจจุบัน
    *   **สาเหตุ-เหตุผล:** เพื่อเชื่อมโยงการเรียกฟังก์ชันจาก image ปัจจุบันไปยังที่อยู่จริงของฟังก์ชันใน DLLs อื่นๆ

7.  **ประมวลผล Thread Local Storage (TLS) (ถ้ามี):**
    *   ถ้า image มี TLS Table (ชี้โดย Data Directory `IMAGE_DIRECTORY_ENTRY_TLS`):
        *   Loader จะจัดสรร TLS index ให้กับ image
        *   ถ้ามี **TLS Callbacks** (array of function pointers ใน `IMAGE_TLS_DIRECTORY`) loader จะ **เรียก TLS callbacks เหล่านั้นตามลำดับ**
        *   **สำคัญ:** TLS callbacks จะถูกเรียก **ก่อน** ที่ `AddressOfEntryPoint` ของ image จะถูกเรียก!
    *   **สาเหตุ-เหตุผล:** TLS ให้พื้นที่ข้อมูลแยกสำหรับแต่ละ thread TLS callbacks มักใช้ในการ initialize data หรือรันโค้ดบางอย่างก่อน main entry point
    *   **Cybersecurity Relevance:** มัลแวร์มักใช้ TLS callbacks ในการทำ anti-debugging, anti-VM, หรือเป็นจุดเริ่มต้นของการ unpack โค้ด (OEP อาจจะอยู่ใน TLS callback ไม่ใช่ `AddressOfEntryPoint` ปกติ)

8.  **(สำหรับ DLLs) เรียก `DllMain` Entry Point:**
    *   ถ้า image ที่กำลังโหลดเป็น DLL และมี `DllMain` function (entry point ของ DLL, ระบุโดย `AddressOfEntryPoint` ใน Optional Header และ subsystem ไม่ใช่ Native):
        *   Loader จะเรียก `DllMain` ของ DLL นั้นด้วย `fdwReason` เป็น `DLL_PROCESS_ATTACH`
        *   `DllMain` สามารถทำการ initialize ที่จำเป็นสำหรับ DLL นั้นได้
        *   **ข้อควรระวัง:** การทำงานที่ซับซ้อนใน `DllMain` (เช่น การโหลด DLL อื่น, การสร้าง thread) อาจทำให้เกิด deadlock หรือปัญหาอื่นๆ ได้ (Loader Lock)
    *   **สาเหตุ-เหตุผล:** เพื่อให้ DLL สามารถเตรียมตัวเองให้พร้อมใช้งานเมื่อถูกโหลดเข้า process

9.  **(สำหรับ EXEs) โอนการควบคุมไปยัง Entry Point:**
    *   ถ้า image ที่กำลังโหลดเป็น .EXE หลัก:
        *   หลังจากที่ .EXE และ dependencies ทั้งหมดถูกโหลดและ resolve เรียบร้อยแล้ว loader จะโอนการควบคุม (jump) ไปยัง `AddressOfEntryPoint` (RVA) ของ .EXE นั้น (บวกกับ `ActualImageBase`)
        *   ณ จุดนี้ โปรแกรม .EXE จะเริ่มทำงานตามโค้ดที่ผู้พัฒนาเขียนไว้ (เช่น `main()`, `WinMain()`)
    *   **สาเหตุ-เหตุผล:** เพื่อเริ่มการทำงานของโปรแกรมหลัก

**กระบวนการนี้อาจมีการปรับเปลี่ยนเล็กน้อยขึ้นอยู่กับ flags และคุณสมบัติของ PE file เช่น:**
*   **Delay-Loaded DLLs:** (ชี้โดย `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`) DLLs เหล่านี้จะไม่ถูกโหลดทันที แต่จะมี stub function ที่จะโหลด DLL และ resolve API เมื่อ API นั้นถูกเรียกใช้ครั้งแรกจริงๆ
*   **.NET Executables:** (ชี้โดย `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`) Loader จะโหลด Common Language Runtime (CLR) (เช่น `mscoree.dll`) แล้ว CLR จะรับผิดชอบในการจัดการ .NET assembly นั้นต่อไป Entry point ของ .NET PE มักจะชี้ไปยัง stub เล็กๆ ที่เรียกว่า `_CorExeMain` หรือ `_CorDllMain` ใน `mscoree.dll`

## 14.3 Cybersecurity Relevance ของ PE Loading Process

การทำความเข้าใจ PE loading process มีความสำคัญอย่างยิ่งในงาน Cybersecurity:

1.  **การวิเคราะห์มัลแวร์:**
    *   **Static Analysis:** การตรวจสอบ PE headers และ data directories ช่วยให้คาดเดาได้ว่า loader จะจัดการกับไฟล์อย่างไร (เช่น จะ relocate ไหม, จะ import API อะไรบ้าง, มี TLS callbacks หรือไม่)
    *   **Dynamic Analysis (Debugging):** สามารถตั้ง breakpoint ณ จุดต่างๆ ของ loading process (เช่น ก่อน/หลัง TLS callbacks, ก่อน/หลัง `DllMain`, ก่อน entry point หลัก) เพื่อสังเกตพฤติกรรมของมัลแวร์ในระหว่างการโหลด
    *   **Unpacking:** Packers จำนวนมากจะ unpack โค้ดเดิม (OEP) ในระหว่าง loading process (อาจจะใน TLS callback หรือ entry point ของ packer stub) การเข้าใจ loading process ช่วยในการหา OEP

2.  **เทคนิคการหลบเลี่ยง (Evasion Techniques):**
    *   **TLS Callbacks:** มัลแวร์ใช้เป็นจุดซ่อนโค้ด anti-analysis หรือ unpacking
    *   **Manual DLL Loading/API Resolution:** มัลแวร์อาจหลีกเลี่ยงการใช้ Import Table ปกติ แต่จะโหลด DLLs และ resolve APIs ด้วยตัวเองใน runtime (ใช้ `LoadLibrary` และ `GetProcAddress`) เพื่อซ่อน API calls จาก static analysis
    *   **Process Hollowing:** มัลแวร์สร้าง process ใหม่ในสถานะ suspended, unmap image เดิมของ process นั้น, แล้ว map image ของมัลแวร์เองเข้าไปแทนที่ จากนั้นก็แก้ไข entry point และ resume process
    *   **Reflective DLL Injection:** มัลแวร์มี PE loader ของตัวเองฝังอยู่ สามารถโหลด DLL (ที่เป็น byte array ใน memory) เข้าไปใน process ใดๆ ก็ได้โดยไม่ต้องให้ DLL นั้นอยู่บนดิสก์ และไม่ต้องผ่าน Windows Loader ปกติ
    *   **Manipulating PE Headers:** มัลแวร์อาจแก้ไขค่าใน PE headers (เช่น `AddressOfEntryPoint`, `SizeOfImage`, section characteristics) เพื่อหลอก loader หรือเครื่องมือวิเคราะห์

3.  **Forensics และ Incident Response:**
    *   การตรวจสอบ memory dump ของ process ที่น่าสงสัย อาจพบร่องรอยของ PE image ที่ถูกโหลดอย่างผิดปกติ (เช่น mapped ที่ VA แปลกๆ, section permissions ที่ไม่ถูกต้อง)
    *   การเข้าใจว่า DLLs ถูกโหลดอย่างไร ช่วยในการติดตามว่ามัลแวร์ component ใดทำงานร่วมกับ component อื่นอย่างไร

4.  **Development of Security Tools:**
    *   เครื่องมือ HIPS (Host-based Intrusion Prevention System) หรือ EDR (Endpoint Detection and Response) อาจ monitor PE loading process เพื่อตรวจจับพฤติกรรมที่น่าสงสัย (เช่น การโหลด DLL จาก path ที่ไม่น่าเชื่อถือ, การเรียก TLS callbacks ที่อันตราย)

## 14.4 สรุป

กระบวนการโหลด PE file เป็นการทำงานร่วมกันที่ซับซ้อนระหว่าง Kernel และ User-mode Loader (ใน `ntdll.dll`) ซึ่งเกี่ยวข้องกับการอ่านและตีความข้อมูลจากส่วนต่างๆ ของ PE file (DOS Header, PE Headers, Section Table, Data Directories) เพื่อ map image เข้าสู่ memory, แก้ไข absolute addresses (relocation), เชื่อมโยงไปยัง DLLs อื่น (imports), และท้ายที่สุดคือเริ่มการทำงานของโค้ด

ความเข้าใจในกระบวนการนี้ไม่เพียงแต่ช่วยให้เห็นภาพรวมว่า PE format ถูกนำมาใช้งานจริงอย่างไร แต่ยังเป็นกุญแจสำคัญในการทำความเข้าใจเทคนิคขั้นสูงต่างๆ ที่มัลแวร์ใช้ในการทำงานและหลบเลี่ยงการตรวจจับ รวมถึงเป็นพื้นฐานในการพัฒนาเครื่องมือและเทคนิคในการป้องกันและวิเคราะห์ภัยคุกคามทางไซเบอร์

ในบทต่อไป เราจะเจาะลึกเรื่อง **การเชื่อมโยง (Linking) และการโหลด Dynamic-Link Libraries (DLLs)** เพิ่มเติม เพื่อให้เข้าใจบทบาทของ DLLs ในระบบนิเวศของ Windows ได้ชัดเจนยิ่งขึ้น
