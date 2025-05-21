---
date: 2025-01-19
title: PE Format บทที่ 19 - PE Format กับ Digital Forensics และ Incident Response
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: ไฟล์ Portable Executable (PE) มักจะเป็นหนึ่งในหลักฐานชิ้นสำคัญที่นักวิเคราะห์ต้องตรวจสอบ เมื่อเกิดเหตุการณ์ความมั่นคงปลอดภัย
---

# บทที่ 19 - PE Format กับ Digital Forensics และ Incident Response

ในโลกของ Digital Forensics (นิติวิทยาศาสตร์ดิจิทัล) และ Incident Response (IR - การตอบสนองต่อเหตุการณ์ละเมิดความมั่นคงปลอดภัย) ไฟล์ Portable Executable (PE) มักจะเป็นหนึ่งในหลักฐานชิ้นสำคัญที่นักวิเคราะห์ต้องตรวจสอบ เมื่อเกิดเหตุการณ์ความมั่นคงปลอดภัย เช่น การบุกรุกเข้าระบบ, การแพร่กระจายของมัลแวร์, หรือการโจมตีทางไซเบอร์อื่นๆ ไฟล์ PE ที่น่าสงสัย (เช่น executables, DLLs ที่ไม่รู้จัก) ที่พบบนระบบที่ถูกบุกรุก หรือใน memory dump สามารถให้เบาะแสที่สำคัญเกี่ยวกับสิ่งที่เกิดขึ้น, ใครเป็นผู้กระทำ, และจะป้องกันเหตุการณ์ซ้ำรอยได้อย่างไร

ความรู้ความเข้าใจในโครงสร้าง PE format จึงเป็นทักษะที่จำเป็นสำหรับผู้ปฏิบัติงานด้าน DFIR เพื่อให้สามารถสกัดข้อมูลที่เป็นประโยชน์, ประเมินความน่าเชื่อถือของไฟล์, และเชื่อมโยงไฟล์นั้นเข้ากับกิจกรรมที่เป็นอันตรายได้

## 19.1 บทบาทของ PE File Analysis ในกระบวนการ DFIR

1.  **Identification (การระบุตัวตน):**
    *   ยืนยันว่าไฟล์ต้องสงสัยเป็น PE file จริงหรือไม่ (ดู "MZ" และ "PE" signatures)
    *   ระบุประเภท (EXE, DLL, SYS) และสถาปัตยกรรม (32-bit/64-bit)
    *   คำนวณ hashes (MD5, SHA1, SHA256) เพื่อใช้เปรียบเทียบกับฐานข้อมูลมัลแวร์ (เช่น VirusTotal) หรือ IOCs ที่ทราบ

2.  **Scoping (การประเมินขอบเขต):**
    *   วิเคราะห์ PE files ที่พบบนหลายๆ ระบบ เพื่อดูว่าการติดเชื้อหรือการบุกรุกแพร่กระจายไปกว้างแค่ไหน
    *   Timestamp (`TimeDateStamp` ใน COFF Header, timestamp ของ resources) อาจช่วยในการสร้างไทม์ไลน์ของเหตุการณ์ (แม้จะสามารถปลอมแปลงได้)

3.  **Containment and Eradication (การจำกัดและกำจัด):**
    *   ข้อมูลจาก PE analysis (เช่น ชื่อไฟล์, hashes, registry keys ที่เกี่ยวข้อง, C&C servers) ช่วยในการสร้างกฎสำหรับบล็อกไฟล์นั้นบน endpoint หรือใน network, ลบไฟล์ที่เป็นอันตราย, และทำความสะอาด registry

4.  **Lessons Learned and Hardening (บทเรียนและการเสริมความแข็งแกร่ง):**
    *   ทำความเข้าใจว่ามัลแวร์ PE ทำงานอย่างไร, ใช้เทคนิคอะไร, และมีช่องโหว่ใดที่ถูกใช้ เพื่อนำไปปรับปรุงมาตรการป้องกันในอนาคต

## 19.2 ข้อมูลจาก PE Format ที่มีประโยชน์ในงาน DFIR

นักวิเคราะห์ DFIR จะตรวจสอบส่วนต่างๆ ของ PE file คล้ายกับที่นักวิเคราะห์มัลแวร์ทำ แต่จะมองในมุมของการเก็บหลักฐานและเชื่อมโยงกับเหตุการณ์:

1.  **Timestamps:**
    *   **`TimeDateStamp` (COFF Header):** เวลาคอมไพล์/ลิงก์ของ PE file
    *   **`TimeDateStamp` (Export Directory):** เวลาสร้างข้อมูล export
    *   **`TimeDateStamp` (Resource Directory):** เวลาสร้างข้อมูล resource
    *   **`TimeDateStamp` (Debug Directory):** เวลาสร้างข้อมูล debug
    *   **Authenticode Timestamp (ใน Digital Signature):** ถ้าไฟล์มี signature ที่มี timestamp, จะให้เวลาที่น่าเชื่อถือได้มากกว่าว่าไฟล์มีอยู่ ณ เวลานั้น (แม้ตัวไฟล์เองอาจถูก timestomp ทีหลัง)
    *   **การใช้งานใน DFIR:**
        *   ช่วยสร้างไทม์ไลน์: ไฟล์นี้ถูกสร้างขึ้นเมื่อไหร่? สอดคล้องกับช่วงเวลาที่เกิดเหตุการณ์หรือไม่?
        *   Timestomping Detection: เปรียบเทียบ PE timestamps กับ MACE (Modification, Access, Creation, Entry Modified) timestamps ของไฟล์ใน file system (จาก MFT ใน NTFS) หาก PE timestamp ใหม่กว่า MACE times (โดยเฉพาะ Creation time) หรือมีค่าที่ผิดปกติ (เช่น ปี 1970) อาจบ่งชี้ถึงการ timestomp โดยผู้โจมตี
        *   เปรียบเทียบ timestamps ของ PE files หลายๆ ตัวที่น่าสงสัย เพื่อดูว่าอาจจะมาจาก campaign หรือผู้สร้างเดียวกันหรือไม่

2.  **Import Table (IAT):**
    *   **API Calls:** บอกถึงความสามารถของ PE file (เช่น network, file, registry, process manipulation)
    *   **การใช้งานใน DFIR:**
        *   เชื่อมโยงกับกิจกรรมที่สังเกตเห็นบนระบบ: ถ้าพบ log การเชื่อมต่อเครือข่ายที่น่าสงสัย และ PE file ที่น่าสงสัย import network APIs ก็อาจจะเกี่ยวข้องกัน
        *   ระบุพฤติกรรมที่เป็นอันตราย: เช่น การ import API ที่ใช้ในการลบไฟล์, เข้ารหัสข้อมูล, หรือขโมย credentials

3.  **Export Table (EAT) (สำหรับ DLLs):**
    *   **Exported Functions:** บอกว่า DLL นี้ให้บริการอะไร
    *   **การใช้งานใน DFIR:**
        *   ถ้า DLL ที่ไม่รู้จักถูกโหลดโดย process ที่ถูกกฎหมาย การดู exports อาจช่วยให้เข้าใจว่า DLL นั้นทำอะไร (เช่น อาจเป็น backdoor ที่ export ฟังก์ชันสำหรับรับคำสั่ง)
        *   DLL ที่ใช้ใน DLL Hijacking มักจะ export ฟังก์ชันที่มีชื่อเหมือนกับ DLL ที่ถูกต้อง (เพื่อ proxy การเรียก)

4.  **Resource Section (`.rsrc`):**
    *   **Version Information (`RT_VERSION`):**
        *   `CompanyName`, `ProductName`, `FileDescription`, `OriginalFilename`: ข้อมูลนี้อาจถูกปลอมแปลงให้เหมือนโปรแกรมที่ถูกกฎหมาย หรืออาจเปิดเผยชื่อโปรเจกต์ของมัลแวร์
        *   เปรียบเทียบกับโปรแกรมที่ถูกกฎหมายที่มีชื่อคล้ายกัน
    *   **String Table (`RT_STRING`):** อาจมี UI strings, error messages, หรือ IOCs อื่นๆ
    *   **Custom Data (`RT_RCDATA`):** อาจมี configuration, payloads ที่เข้ารหัส, หรือ PE file อื่นที่ถูกฝัง
    *   **Manifest (`RT_MANIFEST`):** `requestedExecutionLevel` อาจบ่งชี้ว่าโปรแกรมต้องการสิทธิ์ admin
    *   **การใช้งานใน DFIR:**
        *   หา IOCs เพิ่มเติม
        *   ระบุความพยายามในการปลอมตัว (masquerading)
        *   สกัด payloads ที่ซ่อนอยู่เพื่อวิเคราะห์ต่อ

5.  **Strings ใน Sections อื่นๆ:**
    *   Strings ที่อยู่ใน `.data`, `.rdata`, หรือแม้แต่ `.text` (ถ้ามีการสร้าง string ใน stack หรือ heap)
    *   **การใช้งานใน DFIR:** คล้ายกับ String Table ใน resources แต่ต้องระวัง false positives มากขึ้น

6.  **Digital Signature (`IMAGE_DIRECTORY_ENTRY_SECURITY`):**
    *   **Authenticity and Integrity:** ตรวจสอบว่า signature valid หรือไม่, signer เป็นใคร, certificate chain ถูกต้องหรือไม่
    *   **การใช้งานใน DFIR:**
        *   ไฟล์ที่ไม่มี signature หรือ signature ไม่ valid (ทั้งที่ควรจะมี เช่น system file) เป็นสัญญาณอันตราย
        *   Signer ที่ไม่รู้จัก หรือ signer ที่เคยมีประวัติเกี่ยวข้องกับมัลแวร์
        *   ไฟล์ที่ถูก sign ด้วย certificate ที่ถูกขโมยมา

7.  **Section Table Characteristics:**
    *   **Section Names:** ชื่อแปลกๆ หรือชื่อ packer
    *   **Permissions:** W+X sections, code section ที่ writable, data section ที่ executable
    *   **Entropy:** Section ที่มี entropy สูง (อาจเป็น packed/encrypted data)
    *   **การใช้งานใน DFIR:**
        *   ระบุไฟล์ที่น่าจะถูก pack หรือ obfuscate
        *   หา memory regions ที่น่าสงสัยที่อาจมีโค้ดหรือข้อมูลอันตราย (ถ้าทำ memory forensics)

8.  **Debug Information (`IMAGE_DIRECTORY_ENTRY_DEBUG`):**
    *   **PDB Path (Program Database Path):** ถ้ามี, path ไปยังไฟล์ .PDB (ที่เก็บ debug symbols) อาจเปิดเผยชื่อ user, ชื่อโปรเจกต์, หรือ path ในเครื่องของผู้พัฒนา
    *   **การใช้งานใน DFIR:**
        *   อาจให้เบาะแสเกี่ยวกับแหล่งที่มาของมัลแวร์ (attribution) แม้จะสามารถปลอมแปลงได้
        *   มัลแวร์ที่คอมไพล์ในโหมด debug โดยไม่ได้ตั้งใจ อาจทิ้ง PDB path ไว้

9.  **PE Header Fields ที่น่าสนใจเพิ่มเติม:**
    *   **`Subsystem` (Optional Header):** `NATIVE` subsystem สำหรับไฟล์ที่รันใน kernel หรือเป็น service ระดับต่ำ
    *   **`DllCharacteristics` (Optional Header):** การไม่รองรับ ASLR/DEP/CFG
    *   **`AddressOfEntryPoint`:** ชี้ไปยังตำแหน่งที่แปลก (เช่น resource section, non-executable section)
    *   **การใช้งานใน DFIR:** ช่วยประเมินความซับซ้อนและความเสี่ยงของไฟล์

## 19.3 PE File Analysis จาก Memory Dumps

ในงาน DFIR การวิเคราะห์ memory dump ของ process ที่น่าสงสัย หรือ full physical memory dump ของระบบ เป็นสิ่งสำคัญมาก PE files (ทั้ง .EXE และ DLLs) ที่ถูกโหลดเข้า memory อาจมีลักษณะที่แตกต่างจากไฟล์บนดิสก์ (on-disk file):

1.  **Unpacked/Decrypted Code/Data:**
    *   ถ้ามัลแวร์ถูก pack หรือเข้ารหัสไว้บนดิสก์ มันจะต้อง unpack/decrypt ตัวเองใน memory เพื่อทำงาน
    *   การวิเคราะห์ PE image จาก memory dump อาจทำให้เห็น original code และ data ที่ถูกซ่อนไว้ (ซึ่ง static analysis ของ on-disk file ไม่เห็น)
    *   เครื่องมือ memory forensics (เช่น Volatility, Rekall) สามารถ dump PE images ที่ถูก map ใน memory (เรียกว่า "module dump" หรือ "process dump") ออกมาเป็นไฟล์ เพื่อวิเคราะห์ต่อได้

2.  **IAT Hooking / EAT Hooking:**
    *   Address ใน IAT (หรือ EAT) ของ PE image ใน memory อาจถูกแก้ไขโดย rootkit หรือมัลแวร์อื่น ให้ชี้ไปยังโค้ดอันตราย
    *   การเปรียบเทียบ IAT/EAT จาก memory dump กับ IAT/EAT ที่ควรจะเป็น (จาก on-disk file หรือฐานข้อมูล) สามารถตรวจจับ hooking ได้

3.  **In-Memory Code Injection:**
    *   มัลแวร์อาจ inject โค้ด (shellcode หรือ PE image ที่โหลดแบบ reflective) เข้าไปใน memory region ของ process อื่น โดยที่โค้ดนั้นอาจจะไม่มี PE header ที่สมบูรณ์ หรือมี section permissions ที่น่าสงสัย (เช่น W+X page ที่ไม่ใช่ส่วนหนึ่งของ PE image ที่ถูก map ตามปกติ)
    *   การสแกน memory dump หา PE headers ที่ "ลอย" อยู่ (unlinked modules) หรือ memory pages ที่มี W+X permissions เป็นเทคนิคในการหา code injection

4.  **Process Hollowing / RunPE:**
    *   PE image ใน memory ของ process ที่ถูก hollowed จะเป็น image ของมัลแวร์ ไม่ใช่ image เดิมที่ควรจะเป็น (ตามชื่อ process)
    *   การเปรียบเทียบ PE header (เช่น `ImageBase`, `EntryPoint`, `SizeOfImage`) จาก memory กับ on-disk file ของ process นั้น สามารถตรวจจับ hollowing ได้

5.  **Hidden/Unlinked Modules:**
    *   Rootkits หรือมัลแวร์ขั้นสูงอาจพยายามซ่อน DLLs ที่โหลดใน memory โดยการ unlink มันออกจาก list ของ loaded modules ใน PEB (Process Environment Block)
    *   เครื่องมือ memory forensics สามารถสแกน memory เพื่อหา PE headers ที่ไม่ได้ถูก link ใน PEB (เช่น Volatility's `ldrmodules` vs `malfind` or `dlllist`)

**การใช้ PE Format Knowledge กับ Memory Dumps:**
*   เมื่อ dump PE image จาก memory ออกมาเป็นไฟล์แล้ว นักวิเคราะห์ DFIR จะใช้เครื่องมือ PE analysis แบบเดียวกับที่ใช้กับ on-disk file เพื่อตรวจสอบ headers, sections, imports, exports, etc.
*   ความรู้เรื่อง RVA, `ImageBase`, section alignment, และ memory protection มีความสำคัญอย่างยิ่งในการตีความข้อมูลจาก memory dump และ reconstruct PE structure ที่ถูกต้อง

## 19.4 การสร้าง Timeline และ Correlation

ข้อมูลจาก PE file analysis (เช่น timestamps, IOCs, imports/exports) จะถูกนำมารวมกับข้อมูลจากแหล่งอื่นๆ (เช่น event logs, network logs, file system metadata, registry analysis) เพื่อ:
*   **สร้าง Timeline ของเหตุการณ์ (Timeline Analysis):** ลำดับว่าไฟล์ PE ที่น่าสงสัยปรากฏขึ้นเมื่อไหร่, ถูกรันเมื่อไหร่, มีการสร้างไฟล์หรือ network connection อะไรบ้าง
*   **เชื่อมโยง (Correlate) Artifacts:** หาความสัมพันธ์ระหว่าง PE files ต่างๆ (เช่น DLL ที่ถูกโหลดโดย EXE), ระหว่าง PE file กับ network activity, หรือระหว่าง PE file กับการเปลี่ยนแปลงใน registry
*   **Attribution (ถ้าทำได้):** บางครั้งลักษณะเฉพาะของ PE file (เช่น PDB path, custom packer, C&C protocol) อาจช่วยในการระบุผู้สร้างมัลแวร์หรือกลุ่มผู้โจมตี (แม้จะยากและต้องระวัง false positives)

## 19.5 สรุป

PE format เป็นแหล่งข้อมูลที่ทรงคุณค่าสำหรับนักวิเคราะห์ Digital Forensics และ Incident Response การตรวจสอบ PE headers, sections, data directories, timestamps, และ digital signatures ของไฟล์ต้องสงสัย สามารถให้เบาะแสที่สำคัญเกี่ยวกับธรรมชาติของภัยคุกคาม, ขอบเขตของเหตุการณ์, และวิธีการที่ผู้โจมตีใช้

ความสามารถในการวิเคราะห์ PE files ทั้งจาก on-disk evidence และจาก memory dumps (ซึ่งอาจเปิดเผย unpacked/injected code) เป็นทักษะหลักที่ช่วยให้ทีม DFIR สามารถตอบสนองต่อเหตุการณ์ได้อย่างมีประสิทธิภาพ, จำกัดความเสียหาย, และป้องกันการโจมตีในอนาคตได้ดียิ่งขึ้น

ในบทต่อไป เราจะมาดู **เครื่องมือต่างๆ ที่ใช้สำหรับการวิเคราะห์ PE File** โดยสรุป
