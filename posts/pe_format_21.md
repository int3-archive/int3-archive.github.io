---
date: 2025-01-21
title: PE Format บทที่ 21 - .NET PE Files, Drivers, Code Signing
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: PE format ซึ่งมักจะพบในการวิเคราะห์ซอฟต์แวร์หรือมัลแวร์ที่ซับซ้อนยิ่งขึ้น
---

# บทที่ 21 - .NET PE Files, Drivers, Code Signing

ในบทนี้ เราจะสำรวจหัวข้อขั้นสูงบางประการที่เกี่ยวข้องกับ PE format ซึ่งมักจะพบในการวิเคราะห์ซอฟต์แวร์หรือมัลแวร์ที่ซับซ้อนยิ่งขึ้น หัวข้อเหล่านี้ได้แก่:

*   **.NET PE Files (Managed Executables):** ไฟล์ PE ที่บรรจุโค้ด .NET ซึ่งต้องการ Common Language Runtime (CLR) ในการทำงาน
*   **Drivers (Kernel-Mode Drivers):** ไฟล์ PE ชนิดพิเศษ (.SYS) ที่ทำงานในระดับ kernel เพื่อควบคุมฮาร์ดแวร์
*   **Code Signing (ลายเซ็นดิจิทัล):** กระบวนการใช้ digital certificates เพื่อรับรองความถูกต้องและแหล่งที่มาของ PE file

หัวข้อเหล่านี้มีความสำคัญในแง่ของ Cybersecurity เพราะมัลแวร์อาจใช้เทคนิคที่เกี่ยวข้องกับหัวข้อเหล่านี้เพื่อหลบเลี่ยงการตรวจจับ, โจมตีระบบในระดับต่ำ, หรือปลอมแปลงตัวเอง

## 21.1 .NET PE Files (Managed Executables)

PE file ที่เขียนด้วยภาษา .NET (เช่น C#, VB.NET) จะแตกต่างจาก PE file ที่เขียนด้วยภาษา native (เช่น C/C++) ตรงที่:

*   **.NET PE ไม่ได้บรรจุ machine code โดยตรง:** แต่จะบรรจุ **Microsoft Intermediate Language (MSIL)** หรือบางครั้งเรียกว่า Common Intermediate Language (CIL) code ซึ่งเป็น assembly language ที่ออกแบบมาสำหรับ Common Language Runtime (CLR)
*   **ต้องใช้ CLR ในการ Run:** เมื่อ .NET PE ถูกโหลด, Windows Loader จะโหลด Common Language Runtime (CLR) ซึ่งเป็น virtual machine ที่ทำหน้าที่:
    *   **JIT Compilation (Just-In-Time Compilation):** แปลง MSIL code เป็น machine code ที่เหมาะสมกับ CPU ของเครื่อง ณ runtime
    *   **Memory Management (Garbage Collection):** จัดการ memory allocation และ deallocation โดยอัตโนมัติ
    *   **Security:** บังคับใช้ code access security (CAS) และตรวจสอบความปลอดภัยของ MSIL code
*   **.NET Metadata:** PE file จะมี metadata จำนวนมาก (เกี่ยวกับ classes, methods, properties, events, dependencies) ที่ CLR ใช้ในการโหลดและรันโปรแกรม

**การระบุ .NET PE File:**
*   Data Directory entry ตัวที่ 14 (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`) ใน Optional Header จะชี้ไปยังโครงสร้าง `IMAGE_COR20_HEADER` (หรือ CLR Header) ที่อยู่ของ .NET metadata
*   ฟิลด์ `COMRuntimeVersion` ใน `IMAGE_COR20_HEADER` จะระบุ CLR version ที่ต้องการ

**โครงสร้าง `IMAGE_COR20_HEADER` (CLR Header):**

```c
typedef struct _IMAGE_COR20_HEADER {
    DWORD           cb;                     // Size of structure in bytes
    WORD            MajorRuntimeVersion;    // Major version of the runtime
    WORD            MinorRuntimeVersion;    // Minor version of the runtime
    DWORD           MetaDataDir;            // RVA of the MetaData directory
    DWORD           MetaDataSize;           // Size of MetaData directory in bytes
    DWORD           Flags;                  // Flags indicating special attributes
    DWORD           EntryPointToken;        // MD Token for the managed entry point
    DWORD           ResourcesDir;           // RVA of the Managed resources directory
    DWORD           ResourcesSize;          // Size of Managed resources directory in bytes
    DWORD           StrongNameSignatureDir; // RVA of the StrongName signature
    DWORD           StrongNameSignatureSize;// Size of the StrongName signature in bytes
    DWORD           CodeManagerTableDir;    // RVA of the Code Manager Table
    DWORD           CodeManagerTableSize;   // Size of the Code Manager Table in bytes
    DWORD           VTableFixupsDir;        // RVA of the VTable Fixup Table
    DWORD           VTableFixupsSize;       // Size of the VTable Fixup Table in bytes
    DWORD           ExportTableDir;         // RVA of the Export Address Table jumps
    DWORD           ExportTableSize;        // Size of the Export Address Table jumps in bytes
    DWORD           ManagedNativeHeaderDir; // RVA of the Managed Native Header
    DWORD           ManagedNativeHeaderSize;// Size of the Managed Native Header in bytes
} IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;
```

**ฟิลด์ที่สำคัญ:**
*   `MetaDataDir`: RVA ของ metadata directory (โครงสร้างข้อมูลที่อธิบาย classes, methods, dependencies ของ .NET assembly)
*   `MetaDataSize`: ขนาดของ metadata directory
*   `EntryPointToken`: Metadata token ที่ระบุ method ที่เป็นจุดเริ่มต้นการทำงานของ .NET assembly

**การวิเคราะห์ .NET PE Files:**

*   **เครื่องมือ:**
    *   **dnSpy:** Open-source .NET decompiler และ debugger ที่ทรงพลังมาก สามารถ decompile MSIL กลับเป็น C#, แก้ไขโค้ด, และ set breakpoints ได้
    *   **ILSpy:** Open-source .NET decompiler (read-only)
    *   **Reflector:** Commercial .NET decompiler (แต่มีรุ่นเก่าที่เป็น freeware)
    *   **PE Viewers:** ยังคงมีประโยชน์ในการดูโครงสร้าง PE พื้นฐาน แต่ข้อมูล .NET จะต้องใช้เครื่องมือเฉพาะในการตีความ
*   **สิ่งที่ต้องทำ:**
    1.  **ใช้ PE viewer ตรวจสอบ Data Directory entry `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` ว่ามีอยู่หรือไม่:** ถ้ามี แสดงว่าเป็น .NET assembly
    2.  **ใช้ dnSpy/ILSpy ในการ decompile MSIL code กลับเป็น C# (หรือ VB.NET):** ศึกษา source code ที่ decompile มาได้เพื่อทำความเข้าใจการทำงานของโปรแกรม
    3.  **ตรวจสอบ dependencies (references):** ดูว่า assembly นี้พึ่งพา .NET assemblies อื่นใด
    4.  **วิเคราะห์ resources:** .NET assembly ก็สามารถมี resources ได้เหมือน PE ทั่วไป
    5.  **Obfuscation:** .NET code ก็สามารถถูก obfuscate ได้เช่นกัน (ใช้ .NET obfuscators) ทำให้การ decompile ได้ code ที่อ่านยาก

**Cybersecurity Relevance:**
*   **.NET Malware:** เป็นที่นิยมมาก เพราะง่ายต่อการเขียนและใช้งาน, .NET framework มี libraries จำนวนมาก, และสามารถรันได้บน Windows ทุกรุ่นที่มี .NET runtime
*   **.NET Obfuscation:** มี obfuscators มากมายสำหรับ .NET ซึ่งทำให้การวิเคราะห์ยากขึ้น
*   **PowerShell Exploits:** PowerShell scripts มักถูกฝังอยู่ใน .NET executables

## 21.2 Drivers (Kernel-Mode Drivers)

**Kernel-mode drivers** เป็น PE files ชนิดพิเศษ (.SYS extension) ที่ทำงานในระดับ kernel (ring 0) ของระบบปฏิบัติการ Windows Drivers มีสิทธิ์เข้าถึงฮาร์ดแวร์โดยตรง และสามารถเข้าถึง memory และ objects ทั้งหมดในระบบ Kernel
*   **อันตราย:** หาก driver มีข้อผิดพลาด หรือถูก compromised, มันสามารถทำให้ทั้งระบบ crash หรือถูกใช้ในการโจมตีระดับสูง

**ลักษณะเฉพาะของ Drivers:**
*   **`Machine` Type:** Driver PE มักจะ compile มาสำหรับสถาปัตยกรรมเฉพาะ (เช่น `IMAGE_FILE_MACHINE_I386` สำหรับ x86, `IMAGE_FILE_MACHINE_AMD64` สำหรับ x64)
*   **`Subsystem` = `IMAGE_SUBSYSTEM_NATIVE` (1) (Optional Header):** ระบุว่าเป็น native application ที่ทำงานใน kernel mode ไม่ใช่ user mode
*   **No Subsystem Required:** Driver ไม่ต้องการ subsystem DLLs (เช่น `kernel32.dll`, `user32.dll`)
*   **Entry Point (`DriverEntry`):** Driver จะมี entry point ที่ชื่อว่า `DriverEntry` (แต่ไม่จำเป็นต้องถูกระบุใน `AddressOfEntryPoint` ใน PE header) ซึ่งเป็นฟังก์ชันที่ Kernel จะเรียกเมื่อโหลด driver
*   **Driver Object:** Kernel สร้าง Driver Object เพื่อเป็น representation ของ driver นั้นในระบบ Kernel Driver Object มี fields ที่สำคัญคือ:
    *   `DriverInit`: Pointer ไปยัง `DriverEntry` function
    *   `DriverUnload`: Pointer ไปยังฟังก์ชันที่จะถูกเรียกเมื่อ unload driver
    *   `MajorFunction`: Array ของ pointers ไปยังฟังก์ชันที่ handles I/O Request Packets (IRPs) สำหรับอุปกรณ์ต่างๆ ที่ driver ควบคุม
*   **Relocation is Essential:** Driver ส่วนใหญ่มักจะต้องถูก relocate ใน memory (ไม่สามารถโหลดที่ `ImageBase` ที่ต้องการได้เสมอไป) ดังนั้น relocation table (`.reloc` section) จะมีความสำคัญมาก

**การวิเคราะห์ Drivers:**
*   **ต้องใช้เครื่องมือที่รองรับ Kernel Debugging:** WinDbg เป็นเครื่องมือหลัก
*   **`!analyze -v`:** Command ใน WinDbg ที่ช่วยในการวิเคราะห์ crash dumps ที่เกิดจาก drivers
*   **โหลด Symbol Files (.PDB):** Driver ที่ดีควรจะมี symbol files ที่ถูกต้อง เพื่อช่วยในการ debugging และ reverse engineering symbol files มักจะเก็บอยู่ใน Microsoft Symbol Server
*   **ใช้ Reverse Engineering เพื่อเข้าใจการทำงาน:** เข้าใจว่า driver ทำอะไรกับฮาร์ดแวร์, มีการ validate input อย่างไร, จัดการ errors อย่างไร
*   **ตรวจสอบ Source Code (ถ้ามี):** Microsoft เผยแพร่ source code ของ drivers ตัวอย่างหลายตัว ซึ่งสามารถใช้เป็น reference

**Cybersecurity Relevance:**
*   **Rootkits:** มัลแวร์ที่ทำงานใน kernel mode มีสิทธิ์ในการควบคุมระบบอย่างสมบูรณ์ สามารถซ่อนตัวเอง, ดักจับข้อมูล, หรือ inject โค้ดเข้าไปใน process อื่นๆ ได้อย่างง่ายดาย
*   **Bootkits:** rootkit ชนิดที่ทำงานตั้งแต่ boot process ก่อนที่ OS จะโหลด ทำให้ตรวจจับและกำจัดยากมาก
*   **Driver Vulnerabilities:** ช่องโหว่ใน drivers สามารถถูกใช้ในการ escalate privileges (จาก user mode เป็น kernel mode) หรือทำให้เกิด BSOD (Blue Screen of Death)

## 21.3 Code Signing (ลายเซ็นดิจิทัล)

**Code signing** คือกระบวนการใช้ digital certificates เพื่อรับรองความถูกต้อง (authenticity) และความสมบูรณ์ (integrity) ของ PE file

**กระบวนการ Code Signing:**
1.  **ผู้พัฒนา (Software Vendor) มี Code Signing Certificate:** ได้รับจาก Certificate Authority (CA) ที่เชื่อถือได้ (เช่น VeriSign, DigiCert)
2.  **Hashing:** ใช้ cryptographic hash function (เช่น SHA256) ในการคำนวณ hash ของ PE file
3.  **Signing:** ใช้ private key ของ code signing certificate ในการเข้ารหัส (encrypt) hash ที่คำนวณได้
4.  **สร้าง Digital Signature:** รวม hash ที่ถูกเข้ารหัส, public key ของ certificate, และข้อมูลอื่นๆ (เช่น timestamp) เข้าด้วยกันในรูปแบบที่กำหนด
5.  **ฝัง Digital Signature ใน PE File:** Digital signature จะถูกเก็บไว้ใน **Attribute Certificate Table** ซึ่งตำแหน่งและขนาดถูกชี้โดย Data Directory entry ตัวที่ 4 (`IMAGE_DIRECTORY_ENTRY_SECURITY`) ใน Optional Header

**การตรวจสอบ Digital Signature:**
1.  **Windows ตรวจสอบ Signature ตอนโหลด PE File:** ตรวจสอบ certificate chain, verify ว่า certificate ยังไม่หมดอายุ/ถูก revoke, และ verify ว่า hash ที่อยู่ใน signature ตรงกับ hash ที่คำนวณจาก PE file จริงๆ
2.  **Authenticode:** เป็นเทคโนโลยีของ Microsoft ที่กำหนดรูปแบบของ digital signatures สำหรับ PE files และกระบวนการตรวจสอบความถูกต้อง
3.  **Code Integrity (CI):** เป็น feature ของ Windows ที่ช่วยป้องกันการโหลด driver หรือ DLL ที่ไม่มี digital signature ที่ถูกต้อง

**โครงสร้าง `WIN_CERTIFICATE` (เริ่มต้นของ Attribute Certificate Table):**

```c
typedef struct _WIN_CERTIFICATE {
    DWORD   dwLength;       // Length of the certificate data
    WORD    wRevision;      // Certificate revision (WIN_CERT_REVISION_1_0 (0x0100), WIN_CERT_REVISION_2_0 (0x0200))
    WORD    wCertificateType;   // Certificate type (see below)
    BYTE    bCertificate[1]; // Certificate data
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
```

**`wCertificateType` ที่สำคัญ:**
*   `WIN_CERT_TYPE_X509 (0x0001)`: X.509 Certificate (common)
*   `WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002)`: PKCS #7 SignedData structure (obsolete)
*   `WIN_CERT_TYPE_TS_STACK_SIGNED (0x0004)`: Terminal Server license (obsolete)

**Cybersecurity Relevance:**
*   **Authenticity Assurance:** Digital signature ช่วยให้ผู้ใช้และระบบปฏิบัติการสามารถมั่นใจได้ว่าไฟล์นั้นมาจากแหล่งที่น่าเชื่อถือ และไม่ได้ถูกแก้ไข (tampered) โดยผู้ไม่หวังดี
*   **Malware Detection:** มัลแวร์มักจะไม่มี digital signature ที่ถูกต้อง (หรือไม่ sign เลย) หรืออาจใช้ stolen/expired certificates
*   **Code Integrity Policies:** องค์กรสามารถบังคับใช้ code signing policies เพื่ออนุญาตให้เฉพาะไฟล์ที่ sign โดย certificate ที่เชื่อถือได้เท่านั้นที่สามารถรันได้ ซึ่งช่วยลดความเสี่ยงจากมัลแวร์

**การตรวจสอบ Code Signatures:**
*   **GUI:** คลิกขวาที่ไฟล์ -> Properties -> Digital Signatures tab
*   **Command Line:** `sigcheck.exe` (จาก Sysinternals Suite), `Get-AuthenticodeSignature` (PowerShell)
*   **API:** `WinVerifyTrust` API

**Cybersecurity Relevance ของ Code Signing:**
*   **Stolen Certificates:** ผู้โจมตีอาจขโมย code signing certificates จากบริษัทซอฟต์แวร์ที่ถูกกฎหมาย แล้วใช้มันในการ sign มัลแวร์ของตัวเอง เพื่อหลีกเลี่ยงการตรวจจับ (supply chain attacks)
*   **Expired/Revoked Certificates:** Signature ที่ใช้ certificate หมดอายุ หรือถูก revoke (ถอน) แล้ว จะไม่น่าเชื่อถือ
*   **Self-Signed Certificates:** มัลแวร์อาจ sign ตัวเองด้วย self-signed certificate (สร้างเอง ไม่ได้มาจาก CA ที่เชื่อถือได้) ซึ่งไม่ควรจะเชื่อถือ
*   **Dual Signing:** บางครั้งผู้โจมตีอาจใช้ valid certificate เพื่อ sign DLL ที่เป็นส่วนหนึ่งของ attack chain แต่ main executable ไม่มี signature เพื่อให้ DLL ถูกโหลดได้อย่างง่ายดาย
*   **Bypassing Code Integrity:** ช่องโหว่บางอย่างอาจทำให้สามารถ bypass การตรวจสอบ code integrity ได้ ทำให้มัลแวร์สามารถโหลด drivers หรือ DLLs ที่ไม่ได้ sign ได้

## 21.4 สรุป

ในบทนี้ เราได้สำรวจหัวข้อขั้นสูงที่เกี่ยวข้องกับ PE format ได้แก่ .NET PE files, drivers, และ code signing แต่ละหัวข้อมีลักษณะเฉพาะและความสำคัญในแง่ของ Cybersecurity ที่แตกต่างกัน

*   **.NET PE:** การวิเคราะห์ต้องใช้เครื่องมือเฉพาะ และมัลแวร์มักจะ obfuscate code
*   **Drivers:** เป็นเป้าหมายที่อันตรายเพราะทำงานใน kernel mode
*   **Code Signing:** ช่วยรับรองความถูกต้องและสมบูรณ์ แต่ certificate ก็สามารถถูกขโมยหรือหมดอายุได้

การมีความรู้ในหัวข้อเหล่านี้ช่วยให้นักวิเคราะห์สามารถรับมือกับมัลแวร์ที่ซับซ้อน และเข้าใจกลไกการทำงานของระบบ Windows ในระดับที่ลึกซึ้งยิ่งขึ้น
