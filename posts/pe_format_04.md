---
date: 2025-01-04
title: PE Format บทที่ 4 - DOS Header และ MS-DOS Stub Program
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: ส่วนประกอบแรกสุดของ PE file นั่นคือ DOS Header และ MS-DOS Stub Program
---

# บทที่ 4 - DOS Header และ MS-DOS Stub Program

ในบทนี้ เราจะเริ่มต้นการเจาะลึกส่วนประกอบแรกสุดของ PE file นั่นคือ **DOS Header** และ **MS-DOS Stub Program** ถึงแม้ว่าส่วนนี้อาจดูเหมือนเป็นมรดกตกทอดจากยุคอดีตและไม่มีบทบาทสำคัญในการทำงานของโปรแกรมบนระบบปฏิบัติการ Windows สมัยใหม่โดยตรง แต่การทำความเข้าใจส่วนนี้ก็ยังคงมีความจำเป็น ทั้งในแง่ของความสมบูรณ์ของโครงสร้าง PE และในบางครั้งอาจมีประโยชน์ในการวิเคราะห์มัลแวร์ที่พยายามใช้ประโยชน์จากส่วนนี้

## 4.1 DOS Header (`IMAGE_DOS_HEADER`)

DOS Header หรือ `IMAGE_DOS_HEADER` เป็นโครงสร้างข้อมูลขนาด 64 bytes ที่อยู่ ณ จุดเริ่มต้นสุดของ PE file ทุกไฟล์ โครงสร้างนี้มีไว้เพื่อความเข้ากันได้ (backward compatibility) กับระบบปฏิบัติการ MS-DOS เป็นหลัก

**โครงสร้างของ `IMAGE_DOS_HEADER` (ในภาษา C):**

```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number (0x5A4D - "MZ")
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header (PE Signature)
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

**คำอธิบายฟิลด์ที่สำคัญ:**

1.  **`e_magic` (WORD - 2 bytes):**
    *   **ค่า:** ต้องเป็น `0x5A4D` ซึ่งแทนตัวอักษร ASCII "MZ" (เรียงแบบ little-endian คือ `4D 5A`)
    *   **ความหมาย:** เป็น "magic number" หรือ "signature" ที่ระบุว่าไฟล์นี้เป็นไฟล์実行 (executable) ในรูปแบบ MZ (ตั้งตามชื่อย่อของ Mark Zbikowski หนึ่งในสถาปนิกของ MS-DOS)
    *   **สาเหตุ-เหตุผล:** ระบบปฏิบัติการและโปรแกรมต่างๆ ใช้ค่านี้ในการตรวจสอบเบื้องต้นว่าเป็นไฟล์ประเภท MZ หรือไม่ หากไม่ใช่ค่านี้ อาจหมายความว่าไฟล์เสียหายหรือเป็นไฟล์ประเภทอื่น
    *   **Cybersecurity Relevance:** มัลแวร์บางตัวอาจพยายามแก้ไขค่านี้เพื่อหลีกเลี่ยงการตรวจจับเบื้องต้น หรือไฟล์ที่เสียหายอาจมีค่านี้ผิดเพี้ยนไป

2.  **`e_lfanew` (LONG - 4 bytes):**
    *   **ค่า:** เป็น offset (ตำแหน่งไบต์) จากจุดเริ่มต้นของไฟล์ (offset 0) ไปยังตำแหน่งที่ **PE Signature (`"PE\0\0"`)** เริ่มต้น
    *   **ความหมาย:** นี่คือฟิลด์ที่ **สำคัญที่สุด** ใน DOS Header สำหรับระบบปฏิบัติการ Windows Loader ของ Windows จะอ่านค่านี้เพื่อ "กระโดด" ข้าม DOS Header และ MS-DOS Stub Program ไปยังส่วนหัวของ PE (NT Headers) โดยตรง
    *   **สาเหตุ-เหตุผล:** เพื่อให้ Windows สามารถค้นหาโครงสร้าง PE ที่แท้จริงได้อย่างรวดเร็ว โดยไม่ต้องสนใจรายละเอียดของส่วน MZ ที่ไม่จำเป็นสำหรับการทำงานบน Windows
    *   **Cybersecurity Relevance:**
        *   มัลแวร์อาจแก้ไขค่า `e_lfanew` ให้ชี้ไปยังตำแหน่งที่ไม่ถูกต้อง หรือชี้ไปยังโค้ดอันตรายที่แฝงตัวอยู่ก่อน PE Header จริง เพื่อพยายามหลอกเครื่องมือวิเคราะห์บางชนิด
        *   ค่า `e_lfanew` ที่เล็กเกินไป (ชี้เข้ามาทับซ้อนกับส่วน DOS Header เอง) หรือใหญ่เกินไป (ชี้ออกไปนอกไฟล์ หรือชี้ไปยังตำแหน่งที่ไม่มี PE Signature) เป็นสัญญาณของไฟล์ที่ผิดปกติหรืออาจเป็นอันตราย
        *   Packers บางตัวอาจตั้งค่า `e_lfanew` ให้ชี้ไปยังตำแหน่งที่ห่างไกลออกไปในไฟล์ โดยส่วนระหว่าง DOS stub กับ PE header อาจเต็มไปด้วย junk data หรือโค้ดที่ถูกเข้ารหัส

**ฟิลด์อื่นๆ ใน `IMAGE_DOS_HEADER`:**

ฟิลด์ส่วนใหญ่ที่เหลือใน `IMAGE_DOS_HEADER` (เช่น `e_cblp`, `e_cp`, `e_crlc`, `e_ss`, `e_sp`, `e_ip`, `e_cs`, `e_lfarlc`) มีความหมายเฉพาะสำหรับ MS-DOS ในการโหลดและรันโปรแกรม 16-bit MZ EXE:
*   `e_cblp`, `e_cp`: เกี่ยวข้องกับขนาดของไฟล์
*   `e_crlc`, `e_lfarlc`: เกี่ยวข้องกับตาราง relocation ของ MZ executable
*   `e_cparhdr`: ขนาดของ EXE header (รวม relocation table) เป็นหน่วย paragraph (1 paragraph = 16 bytes)
*   `e_minalloc`, `e_maxalloc`: จำนวน paragraph ของหน่วยความจำเพิ่มเติมที่โปรแกรมต้องการ
*   `e_ss`, `e_sp`: ค่าเริ่มต้นของ Stack Segment (SS) และ Stack Pointer (SP)
*   `e_ip`, `e_cs`: ค่าเริ่มต้นของ Instruction Pointer (IP) และ Code Segment (CS) ซึ่งเป็น entry point ของโปรแกรม MZ
*   `e_csum`: Checksum (ไม่ค่อยได้ใช้ในปัจจุบัน)
*   `e_ovno`: Overlay number (สำหรับโปรแกรมที่ใช้เทคนิค overlay)
*   `e_res`, `e_res2`: ฟิลด์ที่สงวนไว้ (reserved) ควรมีค่าเป็นศูนย์
*   `e_oemid`, `e_oeminfo`: ข้อมูลเฉพาะสำหรับ OEM (Original Equipment Manufacturer)

**สาเหตุ-เหตุผลที่ยังคงมี DOS Header อยู่:**

1.  **Backward Compatibility:** เหตุผลหลักคือเพื่อให้ไฟล์ PE สามารถถูก "จัดการ" ได้อย่างเหมาะสมบนระบบ MS-DOS หรือระบบที่คาดหวัง MZ format แม้ว่าจะไม่สามารถรันโปรแกรม 32-bit/64-bit ได้ แต่ระบบเหล่านั้นจะไม่ crash และสามารถแสดงข้อความจาก MS-DOS Stub Program ได้
2.  **Identification:** "MZ" signature เป็นวิธีที่ง่ายและรวดเร็วในการระบุว่าไฟล์นั้น "อาจจะ" เป็น executable ของ Windows
3.  **Transition:** `e_lfanew` เป็นกลไกที่เชื่อมโยงจากโลกเก่า (MZ) ไปสู่โลกใหม่ (PE)

## 4.2 MS-DOS Stub Program

MS-DOS Stub Program คือโปรแกรมขนาดเล็ก (optional แต่พบได้ทั่วไป) ที่อยู่ถัดจาก `IMAGE_DOS_HEADER` และอยู่ก่อนตำแหน่งที่ `e_lfanew` ชี้ไป (คือ PE Signature)

**ลักษณะและการทำงาน:**

*   **โค้ด:** เป็นโค้ด Assembly 16-bit ของ MS-DOS จริงๆ
*   **ขนาด:** ไม่มีขนาดที่ตายตัว แต่โดยทั่วไปมักจะเล็ก (ไม่กี่สิบไบต์ถึงร้อยกว่าไบต์)
*   **วัตถุประสงค์:** หากผู้ใช้พยายามรันไฟล์ PE บนระบบปฏิบัติการ MS-DOS (หรือ OS อื่นที่ไม่รู้จัก PE format แต่รู้จัก MZ format) ระบบจะโหลด DOS Header และเริ่มรันโค้ดจาก entry point ที่กำหนดใน DOS Header (`e_cs:e_ip`) ซึ่งโดยทั่วไปจะชี้ไปยังจุดเริ่มต้นของ MS-DOS Stub Program นี้
*   **พฤติกรรมทั่วไป:** Stub program ส่วนใหญ่ที่สร้างโดยคอมไพเลอร์ของ Microsoft (เช่น Visual Studio) จะใช้ MS-DOS INT 21h, AH=09h (Display String) เพื่อแสดงข้อความว่า "This program cannot be run in DOS mode." หรือข้อความที่คล้ายกัน จากนั้นจะจบการทำงาน (INT 21h, AH=4Ch)
    ```assembly
    ; ตัวอย่างโค้ด MS-DOS Stub (แนวคิด)
    MOV DX, OFFSET message   ; โหลด offset ของข้อความ
    MOV AH, 09h              ; ฟังก์ชันแสดงสตริง
    INT 21h                  ; เรียก DOS interrupt
    MOV AX, 4C01h            ; ฟังก์ชันจบโปรแกรม (exit code 1)
    INT 21h                  ; เรียก DOS interrupt
    message DB "This program cannot be run in DOS mode.$"
    ```
*   **การสิ้นสุด:** Stub program จะต้องจบลงก่อนตำแหน่งที่ `e_lfanew` ชี้ไป
*   **การมีอยู่:** Linker ส่วนใหญ่จะใส่ default DOS stub มาให้ แต่โปรแกรมเมอร์สามารถสร้าง DOS stub ของตัวเองและสั่งให้ linker ใช้ stub นั้นแทนได้ (แม้จะไม่ค่อยมีใครทำ)

**สาเหตุ-เหตุผลของการมี MS-DOS Stub Program:**

1.  **User Experience (บน DOS):** ให้ข้อมูลที่เป็นประโยชน์แก่ผู้ใช้ที่พยายามรันโปรแกรมบนแพลตฟอร์มที่ไม่รองรับ แทนที่จะเกิดข้อผิดพลาดที่ไม่สื่อความหมายหรือระบบแฮงค์
2.  **Graceful Degradation:** เป็นรูปแบบหนึ่งของการจัดการความเข้ากันไม่ได้อย่างนุ่มนวล
3.  **Tradition/Legacy:** เป็นส่วนหนึ่งของวิวัฒนาการของ executable formats จาก DOS สู่ Windows

**Cybersecurity Relevance ของ MS-DOS Stub Program:**

*   **Uncommon Stubs:** หาก MS-DOS Stub Program มีขนาดใหญ่ผิดปกติ, มีโค้ดที่ซับซ้อน, หรือไม่ได้แสดงข้อความมาตรฐาน "This program cannot be run in DOS mode." อาจเป็นสัญญาณที่น่าสนใจ
    *   **Packers/Protectors เก่าๆ:** บางครั้ง packers หรือ protectors รุ่นเก่าๆ อาจใส่โค้ดของตัวเองบางส่วนลงใน DOS stub
    *   **Polyglot Files:** ในบางกรณี (แม้จะหายาก) ผู้โจมตีอาจสร้างไฟล์ที่สามารถเป็นได้ทั้ง PE file ที่ถูกต้อง และเป็นโปรแกรม DOS ที่ทำงานบางอย่างได้ด้วย (เช่น dropper ขนาดเล็ก) โดยใช้ประโยชน์จาก DOS stub
    *   **Misleading Information:** มัลแวร์อาจใส่ข้อความที่ไม่เกี่ยวข้องใน stub เพื่อเบี่ยงเบนความสนใจ
*   **Analysis Focus:** โดยทั่วไปแล้ว นักวิเคราะห์มัลแวร์มักจะให้ความสำคัญกับส่วน PE Header และ Sections มากกว่า DOS Header/Stub อย่างไรก็ตาม การตรวจสอบอย่างรวดเร็วว่า DOS stub เป็นแบบมาตรฐานหรือไม่ ก็เป็นส่วนหนึ่งของกระบวนการวิเคราะห์เบื้องต้นที่ดี

**ตัวอย่างการตรวจสอบด้วย PE Viewer:**

เครื่องมือ PE viewer ส่วนใหญ่ (เช่น PE-bear, CFF Explorer, Pestudio) จะแสดงข้อมูลจาก DOS Header และมักจะแสดง hexdump หรือ disassembly ของ MS-DOS Stub Program ด้วย ทำให้นักวิเคราะห์สามารถตรวจสอบค่า `e_magic`, `e_lfanew` และดูว่า DOS stub มีลักษณะอย่างไรได้อย่างรวดเร็ว

ตัวอย่างเช่น:
*   ถ้า `e_magic` ไม่ใช่ "MZ" ไฟล์นั้นอาจไม่ใช่ PE file หรือเสียหาย
*   ถ้า `e_lfanew` ชี้ไปยังตำแหน่งที่ไม่มี "PE" signature ไฟล์นั้นน่าสงสัย
*   ถ้า DOS stub แสดงข้อความ "Rich" Header (ซึ่งเป็น metadata ที่ Microsoft linker เพิ่มเข้ามาและมักจะอยู่หลัง DOS stub แต่ก่อน PE Signature) ก็ถือว่าเป็นเรื่องปกติ แต่ถ้ามีโค้ดแปลกๆ อื่นๆ ก็ควรตรวจสอบเพิ่มเติม

## 4.3 "Rich" Header (ส่วนเพิ่มเติมที่มักพบ)

ถึงแม้จะไม่ใช่ส่วนหนึ่งของ `IMAGE_DOS_HEADER` หรือ MS-DOS Stub Program ตามมาตรฐาน แต่มีโครงสร้างข้อมูลอีกอย่างหนึ่งที่มักจะปรากฏอยู่ระหว่าง MS-DOS Stub Program และ PE Signature (หรืออาจจะทับซ้อนบางส่วนของ stub ที่ไม่ได้ใช้งาน) นั่นคือ **"Rich" Header** (หรือบางครั้งเรียกว่า "MSVC Stub")

*   **ผู้สร้าง:** ถูกเพิ่มเข้ามาโดย Microsoft Linker (ตั้งแต่ Visual Studio รุ่นใหม่ๆ)
*   **ลักษณะ:** เป็นข้อมูลที่ถูก XOR ด้วยคีย์เฉพาะ ("Rich" signature) และประกอบด้วยข้อมูลเกี่ยวกับสภาพแวดล้อมการคอมไพล์ เช่น เวอร์ชั่นของคอมไพเลอร์และ linker ที่ใช้, จำนวนครั้งที่แต่ละเครื่องมือถูกใช้ในการ build โปรแกรมนั้น
*   **ตำแหน่ง:** โดยทั่วไปจะอยู่หลังโค้ด "This program cannot be run in DOS mode." และจบด้วย signature "Rich" ตามด้วยค่า XOR key
*   **การระบุ:** มักจะเริ่มต้นด้วย signature "DanS" (เมื่อยังไม่ได้ XOR) และจบด้วย "Rich" (หลัง XOR)
*   **Cybersecurity Relevance:**
    *   **Fingerprinting Build Environment:** ข้อมูลจาก Rich Header สามารถใช้ในการระบุเครื่องมือและเวอร์ชันที่ใช้สร้างมัลแวร์ ซึ่งอาจช่วยในการ attribution หรือการจัดกลุ่มมัลแวร์
    *   **Anomaly Detection:** หาก Rich Header หายไปจากไฟล์ที่คาดว่าควรจะมี (เช่น ไฟล์ที่คอมไพล์ด้วย MSVC) หรือมีรูปแบบที่ผิดปกติ อาจบ่งชี้ว่าไฟล์ถูกดัดแปลงหรือสร้างด้วยเครื่องมือที่ไม่ใช่มาตรฐาน
    *   **False Positives/Negatives:** บางครั้งมัลแวร์อาจพยายามลบหรือปลอมแปลง Rich Header เพื่อหลีกเลี่ยงการถูก fingerprint

## 4.4 สรุป

DOS Header และ MS-DOS Stub Program เป็นส่วนประกอบแรกสุดของ PE file ซึ่งมีบทบาทหลักในด้านความเข้ากันได้กับระบบรุ่นเก่า ฟิลด์ `e_magic` ("MZ") ใช้ระบุประเภทไฟล์เบื้องต้น และ `e_lfanew` เป็นตัวชี้สำคัญที่นำทาง Windows loader ไปยังโครงสร้าง PE ที่แท้จริง MS-DOS Stub Program (และ Rich Header ที่มักพบร่วมด้วย) โดยทั่วไปมีพฤติกรรมมาตรฐาน แต่ในบางสถานการณ์ทาง Cybersecurity การตรวจสอบความผิดปกติในส่วนเหล่านี้อาจให้เบาะแสที่เป็นประโยชน์ได้

แม้ว่าในทางปฏิบัติ Windows loader จะ "กระโดด" ข้ามส่วนนี้ไปอย่างรวดเร็ว แต่การทำความเข้าใจโครงสร้างและวัตถุประสงค์ของมันก็ช่วยเติมเต็มความรู้เกี่ยวกับ PE format ให้สมบูรณ์ยิ่งขึ้น

ในบทต่อไป เราจะเดินทางตาม `e_lfanew` ไปยังส่วนที่สองของ PE file นั่นคือ PE Signature และ COFF File Header ซึ่งเป็นจุดเริ่มต้นของ "NT Headers" ที่มีความสำคัญอย่างยิ่งต่อการทำงานของโปรแกรมบน Windows

