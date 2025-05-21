---
date: 2025-01-12
title: PE Format บทที่ 12 - Base Relocations และการทำงาน
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: เมื่อ PE file ถูกคอมไพล์และลิงก์ มันจะมี Preferred Image Base Address (ระบุในฟิลด์ ImageBase ของ Optional Header) ซึ่งเป็นตำแหน่ง Virtual Address (VA) ที่ linker "คาดหวัง" ว่าไฟล์นี้จะถูกโหลดเข้าไปในหน่วยความจำ
---

# บทที่ 12 - Base Relocations และการทำงาน

เมื่อ PE file ถูกคอมไพล์และลิงก์ มันจะมี **Preferred Image Base Address** (ระบุในฟิลด์ `ImageBase` ของ Optional Header) ซึ่งเป็นตำแหน่ง Virtual Address (VA) ที่ linker "คาดหวัง" ว่าไฟล์นี้จะถูกโหลดเข้าไปในหน่วยความจำ หาก Windows loader สามารถโหลดไฟล์ PE ณ ตำแหน่ง `ImageBase` ที่ต้องการนี้ได้ ก็จะไม่มีปัญหาอะไรมากนัก

แต่ในความเป็นจริง Virtual Address Space (VAS) ของ process อาจมี DLL อื่นหรือ memory region อื่นที่ถูกจองไว้ ณ ตำแหน่ง `ImageBase` ที่ PE file นั้นต้องการแล้ว ในกรณีนี้ Windows loader จะต้อง **relocate** (ย้าย) PE image นั้นไปยัง `ImageBase` อื่นที่ยังว่างอยู่

ปัญหาคือ ภายในโค้ดและข้อมูลของ PE file อาจมี **absolute (hardcoded) virtual addresses** ที่อ้างอิงไปยังตำแหน่งต่างๆ ภายใน image นั้นเอง โดยอิงจาก preferred `ImageBase` เดิม หาก image ถูกย้ายไปโหลดที่ `ImageBase` ใหม่ absolute addresses เหล่านี้จะไม่ถูกต้องอีกต่อไป และจะทำให้โปรแกรมทำงานผิดพลาดหรือ crash ได้

เพื่อแก้ไขปัญหานี้ PE format จึงมีกลไกที่เรียกว่า **Base Relocations** ซึ่งเป็นชุดของข้อมูลที่บอก Windows loader ว่ามี absolute address ใดบ้างใน image ที่ต้องถูก "ปรับปรุง" (patch) ให้ถูกต้องตาม `ImageBase` ใหม่ที่โหลดจริง

## 12.1 ความจำเป็นของ Base Relocations

*   **Executables (.EXE):** โดยทั่วไป .EXE file จะเป็น image แรกที่ถูกโหลดเข้าสู่ process ใหม่ ดังนั้นมันมักจะได้ `ImageBase` ที่ต้องการ (เช่น `0x00400000` สำหรับ 32-bit EXE) ทำให้ไม่จำเป็นต้องทำ relocation เสมอไป อย่างไรก็ตาม หาก EXE นั้นถูกคอมไพล์โดยไม่ได้ตั้งค่า `IMAGE_FILE_RELOCS_STRIPPED` ใน COFF Header และมี relocation table อยู่ มันก็สามารถถูก relocate ได้ (ซึ่งจำเป็นสำหรับ ASLR)
*   **Dynamic-Link Libraries (.DLL):** DLLs มีโอกาสสูงที่จะถูกโหลด ณ `ImageBase` ที่แตกต่างจาก preferred base เพราะ process หนึ่งอาจโหลด DLLs จำนวนมาก และ `ImageBase` ที่ต้องการของ DLL เหล่านั้นอาจซ้ำซ้อนกันได้ ดังนั้น DLLs ส่วนใหญ่ **จำเป็นต้องมี Base Relocation Table** เพื่อให้สามารถทำงานได้อย่างถูกต้องเมื่อถูก relocate
*   **ASLR (Address Space Layout Randomization):** เป็นเทคนิคความปลอดภัยที่สำคัญซึ่ง OS จะสุ่ม `ImageBase` ของ DLLs (และ EXEs ที่รองรับ `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`) ทุกครั้งที่โหลด เพื่อทำให้การโจมตีแบบ memory corruption (เช่น buffer overflow ที่ต้องการทราบตำแหน่งของโค้ด/ข้อมูล) ยากขึ้น ASLR จะทำงานได้ก็ต่อเมื่อ image นั้นมี Base Relocation Table ที่ถูกต้อง

**ถ้าไม่มี Base Relocation Table (หรือถูก stripped):**
*   หาก image ไม่มี relocation table และ loader ไม่สามารถโหลดที่ preferred `ImageBase` ได้ **loader จะไม่สามารถโหลด image นั้นได้เลย** (ยกเว้น image นั้นถูกคอมไพล์มาเป็น Position-Independent Code (PIC) อย่างสมบูรณ์ ซึ่งหายากมากสำหรับ PE files บน Windows โดยเฉพาะ 32-bit)
*   มัลแวร์บางตัวอาจจงใจ stripped relocation table ออก เพื่อบังคับให้ตัวเองถูกโหลดที่ preferred `ImageBase` เท่านั้น (ซึ่งอาจเป็นส่วนหนึ่งของเทคนิค anti-analysis หรือเพื่อความง่ายในการ hardcode addresses)

## 12.2 โครงสร้างของ Base Relocation Table

ข้อมูล Base Relocations ถูกจัดเก็บไว้ใน **Base Relocation Table** ซึ่งโดยทั่วไปจะอยู่ใน section ที่ชื่อว่า `.reloc` ตำแหน่งและขนาดของตารางนี้ (หรือ section ที่มีตารางนี้) ถูกชี้โดย Data Directory entry ตัวที่ 5 (`IMAGE_DIRECTORY_ENTRY_BASERELOC`) ใน Optional Header

Base Relocation Table ไม่ได้เป็นตารางเดียวต่อเนื่อง แต่เป็นชุดของ **Relocation Blocks** (หรือ Relocation Chunks) แต่ละ block จะอธิบาย relocations สำหรับ memory page หนึ่งๆ (โดยทั่วไปคือ 4KB)

**โครงสร้างของแต่ละ Relocation Block:**

แต่ละ block เริ่มต้นด้วยโครงสร้าง `IMAGE_BASE_RELOCATION` ตามด้วยอาร์เรย์ของ WORD (2 bytes) entries ที่ระบุตำแหน่งที่ต้อง patch ภายใน page นั้นๆ

**โครงสร้างของ `IMAGE_BASE_RELOCATION` (ขนาด 8 bytes):**

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;         // RVA of the page/block to be relocated
    DWORD   SizeOfBlock;            // Total size of this relocation block in bytes
                                    // (including this struct and all WORD entries that follow)
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
```

**คำอธิบายฟิลด์ใน `IMAGE_BASE_RELOCATION`:**

1.  **`VirtualAddress` (DWORD - 4 bytes):**
    *   **ความหมาย:** เป็น **RVA** ของจุดเริ่มต้นของ **page (หรือ block) ในหน่วยความจำ** ที่ relocations ใน block นี้จะถูกนำไปใช้ RVA นี้จะถูกปัดเศษลงให้เป็น (multiple) ของ page size (เช่น 4KB)
    *   **ตัวอย่าง:** ถ้า page ที่ต้องการ relocate เริ่มที่ RVA `0x00012345` และ page size คือ `0x1000` (4KB), `VirtualAddress` นี้อาจจะเป็น `0x00012000`

2.  **`SizeOfBlock` (DWORD - 4 bytes):**
    *   **ความหมาย:** ขนาดรวม (เป็น bytes) ของ relocation block นี้ ซึ่งรวมถึงขนาดของ `IMAGE_BASE_RELOCATION` structure เอง (8 bytes) บวกกับขนาดของ WORD entries ทั้งหมดที่ตามมาใน block นี้
    *   **การสิ้นสุด:** Loader จะอ่าน WORD entries ไปเรื่อยๆ จนกว่าจะครบ `SizeOfBlock` หรือจนกว่าจะเจอ WORD entry ที่เป็น `IMAGE_REL_BASED_ABSOLUTE` (type 0) ซึ่งใช้เป็น padding เพื่อให้ `SizeOfBlock` เป็นผลคูณของ 4 bytes
    *   **การไปยัง Block ถัดไป:** เมื่อจบ block หนึ่งแล้ว Loader จะใช้ `SizeOfBlock` นี้เพื่อกระโดดไปยังจุดเริ่มต้นของ `IMAGE_BASE_RELOCATION` structure ถัดไป (ถ้ามี)
    *   **การสิ้นสุดของ Table ทั้งหมด:** Base Relocation Table จะจบลงเมื่อเจอ `IMAGE_BASE_RELOCATION` structure ที่มีทั้ง `VirtualAddress` และ `SizeOfBlock` เป็น 0

**WORD Entries ที่ตามหลัง `IMAGE_BASE_RELOCATION`:**

แต่ละ WORD (2 bytes) entry ที่ตามมาจะถูกแบ่งออกเป็น 2 ส่วน:

*   **Type (4 บิตบนสุด - MSB):** ระบุประเภทของ relocation ที่ต้องทำ
*   **Offset (12 บิตล่างสุด - LSB):** เป็น **offset ภายใน page** (ที่ระบุโดย `VirtualAddress` ของ block) ที่ต้องทำการ patch ค่านี้จะบวกกับ `VirtualAddress` ของ block เพื่อให้ได้ RVA ที่แท้จริงของตำแหน่งที่ต้องแก้ไข

**ตัวอย่างการตีความ WORD entry:**
```
WORD entry = 0x30A0; // สมมติค่า

// Type (4 บิตบน): (0x30A0 >> 12) = 0x3  (IMAGE_REL_BASED_HIGHLOW)
// Offset (12 บิตล่าง): (0x30A0 & 0x0FFF) = 0x0A0
```
ดังนั้น ณ RVA = `(VirtualAddress ของ block) + 0x0A0` จะต้องทำการ relocation ประเภท `IMAGE_REL_BASED_HIGHLOW`

**ประเภท Relocation ที่สำคัญ (`Type` field):**

ค่า `Type` ที่พบบ่อยที่สุดคือ:

*   **`IMAGE_REL_BASED_ABSOLUTE` (0):**
    *   **ความหมาย:** ไม่ต้องทำอะไร เป็น entry ที่ใช้สำหรับ padding เพื่อให้ `SizeOfBlock` เป็นผลคูณของ 4 bytes หรือเพื่อข้ามตำแหน่งที่ไม่ต้อง relocate
    *   **การทำงาน:** Loader จะข้าม entry นี้ไป

*   **`IMAGE_REL_BASED_HIGHLOW` (3):**
    *   **ความหมาย:** ให้ทำการ relocate ค่า **DWORD (32-bit)** เต็มๆ ที่ตำแหน่ง offset นั้น
    *   **การทำงาน:**
        1.  คำนวณ **Delta:** `Delta = (Actual ImageBase) - (Preferred ImageBase)` (ค่า `Actual ImageBase` คือ VA ที่ image ถูกโหลดจริง, `Preferred ImageBase` คือค่า `ImageBase` ใน Optional Header)
        2.  อ่านค่า DWORD เดิมที่ตำแหน่ง RVA (`VirtualAddress ของ block + Offset`)
        3.  บวกค่า DWORD เดิมนั้นด้วย `Delta`
        4.  เขียนค่า DWORD ใหม่กลับไปยังตำแหน่ง RVA เดิม
    *   **การใช้งาน:** นี่คือประเภท relocation ที่พบบ่อยที่สุดสำหรับ PE32 (32-bit) เนื่องจาก absolute addresses ส่วนใหญ่มักจะเป็น 32-bit pointers หรือ RVAs ที่ถูกแปลงเป็น VAs โดยอิงจาก preferred base

*   **`IMAGE_REL_BASED_DIR64` (10):**
    *   **ความหมาย:** ให้ทำการ relocate ค่า **ULONGLONG (64-bit)** เต็มๆ ที่ตำแหน่ง offset นั้น
    *   **การทำงาน:** คล้ายกับ `IMAGE_REL_BASED_HIGHLOW` แต่ทำงานกับค่า 64-bit
    *   **การใช้งาน:** นี่คือประเภท relocation ที่พบบ่อยที่สุดสำหรับ PE32+ (64-bit) เนื่องจาก absolute addresses มักจะเป็น 64-bit pointers

**ประเภท Relocation อื่นๆ (พบน้อยกว่าสำหรับ x86/x64 PE):**
*   `IMAGE_REL_BASED_HIGH` (1): ปรับปรุง 16 บิตบน (high word) ของ 32-bit address
*   `IMAGE_REL_BASED_LOW` (2): ปรับปรุง 16 บิตล่าง (low word) ของ 32-bit address
*   `IMAGE_REL_BASED_HIGHADJ` (4): เกี่ยวข้องกับ high/low adjust pairs
*   `IMAGE_REL_BASED_MIPS_JMPADDR` (5) / `IMAGE_REL_BASED_ARM_MOV32` (5) / `IMAGE_REL_BASED_RISCV_HIGH20` (5): เฉพาะสถาปัตยกรรม
*   `IMAGE_REL_BASED_THUMB_MOV32` (7) / `IMAGE_REL_BASED_RISCV_LOW12I` (7): เฉพาะสถาปัตยกรรม
*   (ยังมีประเภทอื่นๆ สำหรับสถาปัตยกรรมเฉพาะ เช่น MIPS, ARM, PowerPC, Itanium)

## 12.3 กระบวนการทำงานของ Base Relocation โดย Loader

เมื่อ Windows loader ตัดสินใจว่าจะโหลด PE image ที่ `ActualImageBase` ซึ่งแตกต่างจาก `PreferredImageBase` (ค่า `ImageBase` ใน Optional Header) มันจะทำตามขั้นตอนต่อไปนี้:

1.  **คำนวณ Delta:**
    `Delta = ActualImageBase - PreferredImageBase`
    *   ถ้า `Delta` เป็น 0 (คือโหลดที่ preferred base) ก็ไม่จำเป็นต้องทำ relocation (ยกเว้น image ถูก mark ให้ force relocation)

2.  **ค้นหา Base Relocation Table:**
    Loader ใช้ Data Directory entry `IMAGE_DIRECTORY_ENTRY_BASERELOC` เพื่อหา RVA และขนาดของ Base Relocation Table (มักอยู่ใน `.reloc` section)

3.  **วนลูปผ่าน Relocation Blocks:**
    Loader เริ่มอ่าน `IMAGE_BASE_RELOCATION` structure แรกในตาราง

4.  **สำหรับแต่ละ Relocation Block:**
    a.  อ่าน `VirtualAddress` (RVA ของ page) และ `SizeOfBlock`
    b.  ถ้าทั้งคู่เป็น 0 แสดงว่าจบตาราง relocation ทั้งหมดแล้ว
    c.  คำนวณจำนวน WORD entries ที่จะตามมา: `NumberOfEntries = (SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD)`
    d.  วนลูปอ่าน WORD entries ทั้ง `NumberOfEntries` ตัว

5.  **สำหรับแต่ละ WORD Entry:**
    a.  แยก `Type` (4 บิตบน) และ `Offset` (12 บิตล่าง)
    b.  ถ้า `Type` คือ `IMAGE_REL_BASED_ABSOLUTE` (0): ข้ามไปทำ entry ถัดไป
    c.  ถ้า `Type` คือ `IMAGE_REL_BASED_HIGHLOW` (3) (สำหรับ PE32):
        i.   คำนวณ RVA ที่ต้อง patch: `PatchRVA = BlockVirtualAddress + Offset`
        ii.  แปลง `PatchRVA` เป็น pointer ไปยังตำแหน่งใน memory ที่ image ถูก map ไว้
        iii. อ่านค่า `DWORD OriginalValue` จากตำแหน่งนั้น
        iv.  คำนวณค่าใหม่: `NewValue = OriginalValue + Delta`
        v.   เขียน `NewValue` กลับไปยังตำแหน่งเดิม
    d.  ถ้า `Type` คือ `IMAGE_REL_BASED_DIR64` (10) (สำหรับ PE32+):
        i.   ทำคล้ายกับ `HIGHLOW` แต่ทำงานกับ `ULONGLONG (64-bit)` value
    e.  (จัดการ relocation types อื่นๆ ถ้ามี)

6.  **ไปยัง Relocation Block ถัดไป:**
    เมื่อประมวลผล WORD entries ทั้งหมดใน block ปัจจุบันแล้ว Loader จะใช้ `SizeOfBlock` เพื่อกระโดดไปยังจุดเริ่มต้นของ `IMAGE_BASE_RELOCATION` structure ถัดไป และกลับไปทำขั้นตอนที่ 4

กระบวนการนี้จะทำซ้ำจนกว่าจะจบ Base Relocation Table ทั้งหมด หลังจากนั้น image ก็จะถูก relocate อย่างสมบูรณ์ และ absolute addresses ทั้งหมดภายใน image ก็จะชี้ไปยังตำแหน่งที่ถูกต้องตาม `ActualImageBase` ใหม่

## 12.4 Cybersecurity Relevance ของ Base Relocations

1.  **ASLR และความสามารถในการ Relocate:**
    *   DLL หรือ EXE ที่ **ไม่มี** `.reloc` section (หรือมีแต่ไม่ถูกต้อง) และ **ไม่ได้** ตั้งค่า `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` จะไม่สามารถใช้ประโยชน์จาก ASLR ได้เต็มที่ (อาจจะยังถูกสุ่ม base ได้ถ้าเป็น EXE แต่ถ้ามี hardcoded address โดยไม่มี relocation ก็จะ crash)
    *   มัลแวร์ที่ไม่รองรับ ASLR (โดยการ stripped `.reloc` หรือ compile แบบ fixed base) จะมีตำแหน่งใน memory ที่คาดเดาได้ง่ายกว่า ซึ่งทำให้การเขียน exploit หรือการทำ memory analysis ง่ายขึ้น

2.  **Stripped `.reloc` Section:**
    *   ผู้สร้างมัลแวร์บางรายอาจจงใจลบ (`.reloc` section) หรือทำให้ข้อมูล relocation ไม่ถูกต้อง เพื่อ:
        *   **Anti-Analysis:** ทำให้เครื่องมือบางชนิดที่พยายาม relocate image เพื่อวิเคราะห์เกิดข้อผิดพลาด
        *   **Forcing Preferred Base:** บังคับให้ image ถูกโหลดที่ preferred `ImageBase` เท่านั้น (ถ้าตำแหน่งนั้นไม่ว่าง image จะโหลดไม่สำเร็จ) ซึ่งอาจเป็นส่วนหนึ่งของเทคนิค anti-VM หรือ anti-sandbox ที่มีการจอง memory ที่ตำแหน่งนั้นไว้ล่วงหน้า
        *   **Reduced Size:** ลดขนาดไฟล์เล็กน้อย (แต่ประโยชน์น้อยมากเมื่อเทียบกับความเสี่ยง)

3.  **Malformed `.reloc` Section:**
    *   `.reloc` section ที่มีโครงสร้างผิดพลาด (เช่น `SizeOfBlock` ไม่ถูกต้อง, `Offset` ชี้ออกนอก page, `Type` ที่ไม่รู้จัก) อาจทำให้ loader crash หรือทำงานผิดพลาด
    *   มัลแวร์อาจสร้าง `.reloc` ที่ผิดพลาดโดยตั้งใจเพื่อโจมตีเครื่องมือวิเคราะห์ PE ที่ parse ส่วนนี้ไม่ถูกต้อง

4.  **Relocations ที่ชี้ไปยังส่วนที่ไม่ควรมี Absolute Addresses:**
    *   โดยทั่วไป relocation ควรจะอยู่ใน code section (สำหรับ jump/call targets ที่เป็น absolute) หรือ data section (สำหรับ pointers)
    *   ถ้าพบ relocation entry ที่พยายาม patch ข้อมูลใน header, resource section, หรือส่วนที่ไม่คาดคิด อาจเป็นสัญญาณของความผิดปกติ หรือเป็นเทคนิคของ packer ที่ซับซ้อน

5.  **Packers และ Relocations:**
    *   Packers หลายตัวจะทำการ stripped `.reloc` section ของ original code ออกไป แล้วตัว unpacker stub จะทำการ rebuild หรือ patch relocations เองใน memory หลังจาก unpack โค้ดเดิมแล้ว
    *   การวิเคราะห์ `.reloc` section ของ packed file อาจจะไม่ให้ข้อมูลเกี่ยวกับ original code เลย

6.  **Relocation Entries จำนวนมากผิดปกติ:**
    *   Image ที่มี hardcoded absolute addresses จำนวนมาก (ซึ่งไม่ค่อยดีในการออกแบบซอฟต์แวร์) จะมี relocation entries จำนวนมาก
    *   บางครั้งมัลแวร์ที่สร้างด้วยเครื่องมือบางอย่าง หรือถูก obfuscate อาจมี patterns ของ relocation ที่ผิดปกติ

## 12.5 สรุป

Base Relocations เป็นกลไกที่สำคัญอย่างยิ่งใน PE format ที่ช่วยให้ PE images (โดยเฉพาะ DLLs และ EXEs ที่รองรับ ASLR) สามารถถูกโหลดและทำงานได้อย่างถูกต้อง ณ Virtual Address Base ใดๆ ที่แตกต่างจาก preferred `ImageBase` ที่ระบุไว้ตอนคอมไพล์ กลไกนี้ทำงานโดยการ patch (แก้ไข) absolute addresses ทั้งหมดภายใน image ให้สอดคล้องกับ `ImageBase` ที่โหลดจริง โดยใช้ข้อมูลจาก Base Relocation Table (มักอยู่ใน `.reloc` section)

สำหรับนักวิเคราะห์ Cybersecurity, การตรวจสอบการมีอยู่, ความถูกต้อง, และลักษณะของ `.reloc` section สามารถให้เบาะแสเกี่ยวกับความสามารถในการรองรับ ASLR ของ image, เทคนิคที่มัลแวร์อาจใช้ในการหลบเลี่ยงการวิเคราะห์, หรือพฤติกรรมของ packer ได้ การทำความเข้าใจว่า relocation ทำงานอย่างไรช่วยให้สามารถตีความ memory dumps และพฤติกรรมการทำงานของโปรแกรมเมื่อถูกโหลดที่ base address ต่างๆ ได้ดียิ่งขึ้น

ในบทต่อไป เราจะมาดูความแตกต่างที่สำคัญระหว่าง PE32 (สำหรับ 32-bit) และ PE32+ (สำหรับ 64-bit) PE files
