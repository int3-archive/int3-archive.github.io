---
date: 2025-01-17
title: PE Format บทที่ 17 - เทคนิคการซ่อนตัวของมัลแวร์ใน PE Format (PE Obfuscation & Packing)
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: เทคนิคหลักๆ ที่ใช้ในการซ่อนตัว (evasion) และทำให้การวิเคราะห์ซับซ้อนขึ้น (anti-analysis) คือ Obfuscation (การทำให้สับสน) และ Packing (การบีบอัด/เข้ารหัส)
---

# บทที่ 17 - เทคนิคการซ่อนตัวของมัลแวร์ใน PE Format (PE Obfuscation & Packing)

ผู้สร้างมัลแวร์พยายามอย่างต่อเนื่องที่จะทำให้โค้ดของตนเองถูกตรวจจับและวิเคราะห์ได้ยากขึ้น เทคนิคหลักๆ ที่ใช้ในการซ่อนตัว (evasion) และทำให้การวิเคราะห์ซับซ้อนขึ้น (anti-analysis) คือ **Obfuscation (การทำให้สับสน)** และ **Packing (การบีบอัด/เข้ารหัส)** เทคนิคเหล่านี้มักจะส่งผลกระทบโดยตรงต่อโครงสร้างของ PE file หรือวิธีการที่ข้อมูลถูกจัดเก็บและเข้าถึงภายใน PE file ทำให้ static analysis แบบดั้งเดิมมีประสิทธิภาพลดลง

การทำความเข้าใจเทคนิคเหล่านี้เป็นสิ่งสำคัญสำหรับนักวิเคราะห์ Cybersecurity เพื่อที่จะสามารถระบุได้ว่าไฟล์ถูกป้องกันด้วยวิธีใด และเพื่อเลือกใช้เครื่องมือหรือวิธีการที่เหมาะสมในการ "แกะ" (unpack) หรือ "คลี่คลาย" (deobfuscate) มัลแวร์นั้นๆ

## 17.1 Obfuscation (การทำให้สับสน)

Obfuscation คือกระบวนการแก้ไขโค้ดหรือข้อมูลในลักษณะที่ทำให้มนุษย์ (และบางครั้งเครื่องมืออัตโนมัติ) อ่านและทำความเข้าใจได้ยากขึ้น โดยที่ยังคงรักษาฟังก์ชันการทำงานเดิมของโปรแกรมไว้ เป้าหมายหลักคือการชะลอหรือขัดขวางการทำ reverse engineering และการสร้าง signature

**เทคนิค Obfuscation ที่พบบ่อย (บางส่วนอาจไม่กระทบ PE structure โดยตรง แต่กระทบการวิเคราะห์):**

1.  **Dead Code Insertion (การแทรกโค้ดที่ไม่มีผล):**
    *   แทรกคำสั่งหรือบล็อกของโค้ดที่ไม่มีผลต่อการทำงานจริงของโปรแกรม (เช่น `NOP`s จำนวนมาก, การคำนวณที่ผลลัพธ์ไม่ได้ถูกใช้, การกระโดดไปยังโค้ดที่กระโดดกลับมาทันที)
    *   **ผลกระทบ:** ทำให้ disassembly ยาวขึ้นและดูซับซ้อนขึ้นโดยไม่จำเป็น

2.  **Instruction Substitution (การแทนที่คำสั่ง):**
    *   แทนที่คำสั่งง่ายๆ ด้วยลำดับของคำสั่งที่ซับซ้อนกว่าแต่ให้ผลลัพธ์เดียวกัน (เช่น แทน `MOV EAX, 0` ด้วย `XOR EAX, EAX` หรือ `SUB EAX, EAX`)
    *   **ผลกระทบ:** ทำให้โค้ดดูแตกต่างจากรูปแบบปกติ

3.  **Control Flow Obfuscation (การทำให้ Flow การทำงานสับสน):**
    *   **Opaque Predicates:** แทรกเงื่อนไข (predicates) ที่ผลลัพธ์ของมัน (true/false) สามารถทราบได้ล่วงหน้าตอน obfuscation time แต่ดูเหมือนจะเป็น dynamic condition สำหรับ disassembler เงื่อนไขนี้จะควบคุมว่าจะกระโดดไปทางไหน ทำให้ disassembler อาจจะสร้าง control flow graph (CFG) ที่ผิดพลาด
    *   **Control Flow Flattening:** เปลี่ยนโครงสร้าง control flow ปกติ (เช่น if-else, loops) ให้กลายเป็น dispatcher loop ขนาดใหญ่ที่ควบคุมการกระโดดไปยัง basic blocks ต่างๆ ผ่านทาง state variable ทำให้ CFG ดูแบนและตามรอยยาก
    *   **Indirect Jumps/Calls:** ใช้ indirect jumps/calls (เช่น `JMP EAX`, `CALL [EBX+ECX*4]`) ที่ target address ถูกคำนวณใน runtime ทำให้ static analysis ตามรอยได้ยาก
    *   **ผลกระทบ:** ทำให้การทำความเข้าใจลำดับการทำงานของโปรแกรมยากขึ้นมาก

4.  **Data Obfuscation (การทำให้ข้อมูลสับสน):**
    *   **String Encryption/Encoding:** เข้ารหัส (XOR, RC4, AES) หรือ encode (Base64, hex) สตริงสำคัญ (เช่น API names, URLs, C&C commands) แล้วทำการ decrypt/decode ใน runtime ก่อนใช้งาน
    *   **Constant Obfuscation:** แทนที่ค่าคงที่ด้วยนิพจน์ที่คำนวณได้ค่าคงที่นั้น (เช่น แทน `5` ด้วย `(2*3)-1`)
    *   **Array Reordering/Splitting:** สลับลำดับ elements ใน array หรือแบ่ง array หนึ่งออกเป็นหลายๆ ส่วน
    *   **ผลกระทบ:** ทำให้การสกัด IOCs หรือการทำความเข้าใจข้อมูลที่โปรแกรมใช้ยากขึ้น

5.  **API Obfuscation (Dynamic API Resolution):**
    *   แทนที่จะ import API โดยตรงผ่าน Import Table (ซึ่ง static analysis เห็นได้ง่าย) มัลแวร์จะทำการ resolve ที่อยู่ของ API ที่ต้องการใน runtime โดย:
        1.  โหลด DLL ที่ต้องการด้วย `LoadLibraryA`/`LoadLibraryW`
        2.  หาที่อยู่ของ API ด้วย `GetProcAddress`
        3.  เก็บ function pointer ไว้แล้วเรียกผ่าน pointer นั้น
    *   ชื่อ DLL และ API อาจจะถูกเข้ารหัสไว้ก่อน แล้ว decrypt ใน runtime
    *   **ผลกระทบ:** Import Table จะดู "สะอาด" (อาจมีแค่ `LoadLibrary`/`GetProcAddress`) ทำให้ static analysis คาดเดาความสามารถของมัลแวร์ได้ยากมาก

**ผลกระทบของ Obfuscation ต่อ PE Structure:**
*   โดยทั่วไป Obfuscation **ไม่** ได้เปลี่ยนแปลงโครงสร้างหลักของ PE header (เช่น DOS, COFF, Optional Header) มากนัก แต่จะเน้นไปที่การแก้ไขเนื้อหาภายใน code section (`.text`) และ data sections
*   อย่างไรก็ตาม API Obfuscation จะทำให้ Import Table (ชี้โดย `IMAGE_DIRECTORY_ENTRY_IMPORT`) มีขนาดเล็กและไม่สะท้อน API ที่ใช้จริง

## 17.2 Packing (การบีบอัด/เข้ารหัส PE File)

Packing เป็นรูปแบบหนึ่งของ obfuscation ที่ซับซ้อนกว่า โดยที่ PE file เดิม (original PE) ทั้งหมดหรือบางส่วน (โดยเฉพาะ code และ data sections) จะถูก **บีบอัด (compress)** และ/หรือ **เข้ารหัส (encrypt)** แล้วถูกห่อหุ้ม (wrap) ด้วยโค้ดส่วนเล็กๆ ที่เรียกว่า **Packer Stub** หรือ **Unpacker Stub**

เมื่อ PE file ที่ถูก pack ถูกรัน:
1.  Packer Stub (ซึ่งเป็น entry point ใหม่ของ packed file) จะทำงานก่อน
2.  Packer Stub จะทำการ **decompress** และ/หรือ **decrypt** original PE ที่ซ่อนอยู่กลับเข้าไปใน memory (อาจจะ map memory region ใหม่ หรือเขียนทับส่วนเดิม)
3.  Packer Stub อาจจะทำการ **rebuild Import Table** (IAT) ของ original PE โดยการ resolve API ที่ original PE ต้องการใช้ (dynamic API resolution)
4.  Packer Stub อาจจะทำการ **fix relocations** ของ original PE (ถ้าจำเป็น)
5.  สุดท้าย Packer Stub จะ **โอนการควบคุม (jump) ไปยัง Original Entry Point (OEP)** ของ original PE เพื่อให้โปรแกรมเดิมเริ่มทำงาน

**เป้าหมายของ Packing:**
*   **ลดขนาดไฟล์ (Compression):** เป็นเป้าหมายดั้งเดิมของ packer ในยุคแรกๆ (เช่น UPX)
*   **Anti-Static Analysis (Encryption/Obfuscation):** นี่คือเป้าหมายหลักในปัจจุบัน ทำให้ static analysis tools ไม่สามารถเห็น original code และ data ได้โดยตรง
*   **Anti-Debugging/Anti-VM:** Packer stub มักจะมีเทคนิค anti-debugging และ anti-VM เพื่อป้องกันการวิเคราะห์ใน dynamic environment

**Packers ที่รู้จักกันดี:**
*   **UPX (Ultimate Packer for eXecutables):** เป็น packer ที่ใช้การบีบอัด (LZMA) เป็นหลัก ค่อนข้างง่ายในการ unpack
*   **ASPack, PECompact, FSG (Fast Small Good):** Packers รุ่นเก่าที่ยังคงพบเห็น
*   **Themida, VMProtect, Enigma Protector, Armadillo:** เป็น "Software Protectors" ที่ซับซ้อนมาก ใช้เทคนิค virtualization, metamorphism, anti-debugging/VM ขั้นสูง ทำให้การ unpack และ reverse engineering ยากสุดๆ
*   **Custom Packers:** ผู้สร้างมัลแวร์มักจะสร้าง packer ของตัวเอง (หรือดัดแปลง packer ที่มีอยู่) เพื่อให้ตรวจจับได้ยากขึ้น

**ผลกระทบของ Packing ต่อ PE Structure และการวิเคราะห์:**

1.  **PE Headers:**
    *   `AddressOfEntryPoint` (OEP) ใน Optional Header จะชี้ไปยัง Packer Stub ไม่ใช่ OEP ของ original code
    *   Import Table (`IMAGE_DIRECTORY_ENTRY_IMPORT`) ของ packed file มักจะเล็กมาก (อาจมีแค่ `LoadLibrary`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect` ที่ packer stub ใช้) และไม่สะท้อน imports ของ original code
    *   Export Table (`IMAGE_DIRECTORY_ENTRY_EXPORT`) อาจจะหายไปหรือถูกทำลาย (ถ้า original PE เป็น DLL ที่มี exports)
    *   Relocation Table (`IMAGE_DIRECTORY_ENTRY_BASERELOC`) อาจจะหายไป เพราะ packer stub จัดการ relocation เอง
    *   Resource Table (`IMAGE_DIRECTORY_ENTRY_RESOURCE`) อาจจะยังคงอยู่ (บาง packer เก็บไว้) หรือถูก pack/ย้ายไปที่อื่น

2.  **Section Table และ Sections:**
    *   **Section Names:** มักจะมีชื่อแปลกๆ ที่เป็นเอกลักษณ์ของ packer (เช่น "UPX0", "UPX1", ". বেশিরভাগ", "CODE", "DATA" ที่ไม่ใช่ของเดิม)
    *   **Section Sizes (`VirtualSize` vs `SizeOfRawData`):**
        *   Code section ของ packer stub (ที่ entry point ชี้ไป) มักจะมี `SizeOfRawData` เล็ก แต่ `VirtualSize` อาจจะใหญ่กว่า เพื่อรองรับการ unpack original code เข้ามา
        *   Original code/data sections อาจจะมี `SizeOfRawData` ที่เล็กมาก (เพราะถูกบีบอัด/เข้ารหัส) แต่ `VirtualSize` ใหญ่ (ขนาดเดิม) หรืออาจจะถูกรวมเป็น section เดียวที่มี entropy สูง
    *   **Section Permissions (Characteristics):**
        *   Section ที่ packer stub ใช้ในการ unpack มักจะมี permission เป็น Writable and Executable (W+X) ซึ่งเป็นสัญญาณอันตราย
        *   Original code section (.text) ของ packed file มักจะไม่มี `IMAGE_SCN_MEM_EXECUTE` flag (เพราะมันมีแค่ข้อมูลที่ถูก pack) แต่ packer stub จะเปลี่ยน permission นี้ใน memory หลัง unpack
    *   **Entropy:** Section ที่เก็บ original code/data ที่ถูก pack มักจะมี entropy สูงมาก (ใกล้ 8) เนื่องจากข้อมูลถูกบีบอัด/เข้ารหัส

3.  **String Analysis:**
    *   การทำ string analysis บน packed file มักจะไม่พบ strings ที่มีความหมายจาก original code เพราะมันถูกซ่อน/เข้ารหัสไว้ จะเห็นแค่ strings ที่ packer stub ใช้ (อาจมีชื่อ packer)

4.  **Static Disassembly:**
    *   การ disassemble packed file จะเห็นแค่โค้ดของ packer stub ซึ่งมักจะซับซ้อนและเต็มไปด้วย anti-analysis tricks การหา OEP และ original code จาก static disassembly ของ packed file เป็นเรื่องยากมาก

## 17.3 การตรวจจับ Obfuscation และ Packing (Heuristics)

ถึงแม้จะไม่มีวิธีที่สมบูรณ์แบบในการตรวจจับทุกเทคนิค แต่ก็มี heuristics (กฎเกณฑ์จากประสบการณ์) และ indicators ที่ช่วยในการระบุว่า PE file อาจถูก obfuscate หรือ pack:

1.  **PE Header Anomalies:**
    *   Entry point ที่อยู่นอก code section หรืออยู่ท้ายสุดของ code section
    *   Import Table ที่เล็กผิดปกติ หรือมีแค่ API พื้นฐาน (LoadLibrary, GetProcAddress)
    *   Section names ที่แปลกประหลาด หรือซ้ำซ้อน
    *   `SizeOfRawData` ของ code section เป็น 0 หรือเล็กมาก
    *   `VirtualSize` ของ section ใหญ่กว่า `SizeOfRawData` มาก (ที่ไม่ใช่ .bss)
    *   Section ที่มี W+X permissions

2.  **High Entropy:**
    *   ใช้ entropy analyzer ตรวจสอบ sections ถ้ามี section (ที่ไม่ใช่ resource ที่ควรมี entropy สูง เช่น รูปภาพ JPEG) ที่มี entropy ใกล้ 8 แสดงว่าอาจถูก pack/encrypt

3.  **Uncommon Section Characteristics:**
    *   Code section ที่ execute ไม่ได้ หรือ data section ที่ execute ได้

4.  **Suspicious Imports/Exports:**
    *   DLL ที่ export ฟังก์ชันด้วย ordinal only จำนวนมาก
    *   การไม่มี export เลยสำหรับ DLL ที่ควรจะมี

5.  **Presence of Anti-Debugging/Anti-VM Code:**
    *   Packer stub มักจะมีโค้ดที่พยายามตรวจจับ debugger (เช่น `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, timing checks) หรือ virtual machine (เช่น ตรวจสอบ MAC address, disk size, registry keys เฉพาะของ VM)
    *   การเห็น API calls เหล่านี้ในส่วนแรกๆ ของโค้ด (packer stub) เป็นสัญญาณที่ชัดเจน

6.  **Unusual Program Flow in Entry Point:**
    *   โค้ดที่ entry point มีการวนลูปขนาดใหญ่, การเขียนลง memory จำนวนมาก, การเรียก `VirtualAlloc`/`VirtualProtect` แล้วตามด้วยการ jump/call ไปยัง memory ที่เพิ่งจัดสรร/แก้ไข permission อาจเป็น packer stub

7.  **Signature-based Detection (Packer Signatures):**
    *   เครื่องมือ PE analysis บางตัว (เช่น PEiD, Detect It Easy - DIE) มีฐานข้อมูลของ signatures (byte patterns) ของ packer ที่รู้จัก และสามารถระบุได้ว่าไฟล์ถูก pack ด้วย packer ตัวใด (ถ้าเป็น packer ที่รู้จัก)

8.  **Strings:**
    *   การพบ strings ที่เป็นชื่อของ packer (เช่น "UPX!", "ASPack")
    *   การขาดหายไปของ strings ที่คาดหวัง (เช่น API names, error messages)

## 17.4 การรับมือกับ Obfuscation และ Packing

1.  **Obfuscation:**
    *   **Deobfuscation Tools/Scripts:** สำหรับเทคนิค obfuscation ที่เป็นที่รู้จัก อาจมีเครื่องมือหรือ script (เช่น Python) ที่ช่วย deobfuscate ได้ในระดับหนึ่ง (เช่น string deobfuscation)
    *   **Manual Reverse Engineering:** มักจะต้องใช้ disassembler/debugger ในการทำความเข้าใจ control flow ที่ซับซ้อน และค่อยๆ "คลี่คลาย" โค้ดทีละส่วน (symbolic execution, concolic testing อาจช่วยได้)
    *   **Dynamic Analysis:** การรันโค้ดใน debugger แล้วสังเกตค่า registers/memory ณ จุดต่างๆ สามารถช่วยให้เข้าใจผลลัพธ์ของ obfuscated code ได้

2.  **Packing:**
    *   **Manual Unpacking:** เป็นกระบวนการที่ซับซ้อนและใช้เวลามาก โดยทั่วไปคือ:
        1.  รัน packed file ใน debugger
        2.  หาจุดที่ packer stub ทำการ unpack original code เสร็จแล้ว และกำลังจะ jump ไปยัง OEP (Original Entry Point)
        3.  ตั้ง breakpoint ก่อน jump ไป OEP
        4.  เมื่อ breakpoint hit ให้ dump memory region ที่มี original code ที่ unpack แล้วออกมาเป็นไฟล์ใหม่
        5.  Rebuild PE header ของ dumped file (เช่น แก้ไข entry point, rebuild IAT, fix relocations) ซึ่งอาจต้องใช้เครื่องมือช่วย (เช่น Scylla, ImpREC)
    *   **Automatic/Generic Unpackers:** มีเครื่องมือบางตัวที่พยายาม unpack ไฟล์โดยอัตโนมัติ แต่ก็ไม่ได้ผลกับทุก packer โดยเฉพาะ custom packers หรือ protectors ที่ซับซ้อน
    *   **Focus on Behavior (Dynamic Analysis):** ถ้าการ unpack ยากมาก อาจจะต้องเน้นไปที่การทำ dynamic analysis เพื่อสังเกตพฤติกรรมของมัลแวร์หลังจากที่มัน unpack ตัวเองใน memory แล้ว โดยไม่จำเป็นต้องได้ original PE file ที่สมบูรณ์กลับมา

## 17.5 สรุป

Obfuscation และ Packing เป็นความท้าทายหลักในการวิเคราะห์มัลแวร์แบบ static พวกมันถูกออกแบบมาเพื่อซ่อนโค้ดและข้อมูลที่แท้จริงของมัลแวร์ ทำให้การตรวจจับ, การทำ reverse engineering, และการสร้าง signature ยากขึ้น

การทำความเข้าใจเทคนิคเหล่านี้, ผลกระทบต่อ PE structure, และ heuristics ในการตรวจจับ เป็นสิ่งสำคัญสำหรับนักวิเคราะห์ Cybersecurity ถึงแม้ static analysis ของไฟล์ที่ถูกป้องกันอย่างแน่นหนาอาจให้ข้อมูลที่จำกัด แต่ก็ยังสามารถระบุได้ว่าไฟล์นั้น "น่าสงสัย" และต้องการการวิเคราะห์ขั้นสูง (เช่น manual unpacking หรือ dynamic analysis ใน sandbox)

ในบทต่อไป เราจะมาดูว่าความรู้เรื่อง PE format สามารถนำไปใช้ในงาน **Reverse Engineering และการวิเคราะห์ช่องโหว่** ได้อย่างไร
