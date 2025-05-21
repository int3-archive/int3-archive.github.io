---
date: 2025-01-20
title: PE Format บทที่ 20 - เครื่องมือสำหรับการวิเคราะห์ PE File
category: Portable Executable (PE) format
tags:
- Windows
- Portable Executable (PE) format
description: การเลือกใช้เครื่องมือขึ้นอยู่กับวัตถุประสงค์ของการวิเคราะห์ (เช่น static analysis เบื้องต้น, reverse engineering เชิงลึก, unpacking, memory forensics) และความถนัดของผู้ใช้งาน
---

# บทที่ 20 - เครื่องมือสำหรับการวิเคราะห์ PE File

ตลอดหลายบทที่ผ่านมา เราได้กล่าวถึงเครื่องมือต่างๆ ที่ใช้ในการตรวจสอบและวิเคราะห์ PE file เป็นระยะๆ ในบทนี้ เราจะรวบรวมและสรุปเครื่องมือที่สำคัญและเป็นที่นิยมสำหรับงานวิเคราะห์ PE file โดยแบ่งตามประเภทการใช้งาน เพื่อให้มีภาพรวมของ "คลังแสง" (arsenal) ที่สามารถนำไปใช้ได้จริง

การเลือกใช้เครื่องมือขึ้นอยู่กับวัตถุประสงค์ของการวิเคราะห์ (เช่น static analysis เบื้องต้น, reverse engineering เชิงลึก, unpacking, memory forensics) และความถนัดของผู้ใช้งาน ไม่มีเครื่องมือใดที่ดีที่สุดสำหรับทุกสถานการณ์ การรู้จักเครื่องมือหลากหลายและสามารถเลือกใช้ได้อย่างเหมาะสมจึงเป็นสิ่งสำคัญ

## 20.1 PE Viewers / PE Editors / PE Parsers

เครื่องมือกลุ่มนี้ใช้ในการดูโครงสร้างและ metadata ของ PE file โดยละเอียด และบางตัวสามารถแก้ไขค่าใน PE header ได้ (ควรทำด้วยความระมัดระวังอย่างยิ่ง)

1.  **PE-bear:**
    *   **ประเภท:** Open-source PE viewer/editor (Windows)
    *   **จุดเด่น:** User interface ค่อนข้างทันสมัย, แสดงโครงสร้าง PE ได้ละเอียดมาก, มี hex editor ในตัว, สามารถ reconstruct PE จาก memory dump ได้ (เบื้องต้น), มี plugin รองรับ
    *   **การใช้งาน:** เหมาะสำหรับการสำรวจ PE headers, sections, data directories, และการแก้ไขค่าต่างๆ (ถ้าจำเป็น)

2.  **CFF Explorer (Explorer Suite):**
    *   **ประเภท:** Freeware PE viewer/editor (Windows)
    *   **จุดเด่น:** เป็นที่นิยมมานาน, มีฟังก์ชันหลากหลาย เช่น hex editor, disassembler เบื้องต้น, resource editor, import/export viewer, signature scanner (PEiD plugins), dependency walker, process viewer
    *   **การใช้งาน:** เครื่องมืออเนกประสงค์สำหรับการ static analysis เบื้องต้นถึงปานกลาง

3.  **Pestudio:**
    *   **ประเภท:** Freeware PE analysis tool (Windows, มี CLI version)
    *   **จุดเด่น:** เน้นการตรวจจับ indicators ที่น่าสงสัยใน PE file (เช่น blacklisted strings, imports, resources), แสดงข้อมูล version info, manifest, entropy, digital signature, และเชื่อมโยงกับ VirusTotal
    *   **การใช้งาน:** เหมาะสำหรับการ triage และประเมินความเสี่ยงเบื้องต้นของ PE file

4.  **PE Explorer:**
    *   **ประเภท:** Commercial PE viewer/editor/disassembler (Windows)
    *   **จุดเด่น:** มีฟังก์ชันครบครัน รวมถึง resource editor ที่ดี, disassembler, dependency scanner, UPX unpacker, และเครื่องมือแก้ไข PE header
    *   **การใช้งาน:** เป็นเครื่องมือ commercial ที่มีความสามารถสูง

5.  **LordPE:**
    *   **ประเภท:** Freeware PE editor (Windows, ค่อนข้างเก่าแต่ยังใช้ได้)
    *   **จุดเด่น:** มีความสามารถในการแก้ไข PE header ได้ค่อนข้างละเอียด, dump process memory, และแก้ไข running processes (ต้องระวัง)
    *   **การใช้งาน:** มักใช้ในงาน RE ขั้นสูงที่ต้องการแก้ไข PE structure โดยตรง

6.  **`pefile` (Python Library):**
    *   **ประเภท:** Open-source Python library
    *   **จุดเด่น:** ช่วยให้สามารถ parse และเข้าถึงทุกส่วนของ PE file structure ผ่าน Python script ได้อย่างง่ายดาย สามารถอ่าน, แก้ไข (บางส่วน), และเขียน PE file ใหม่ได้
    *   **การใช้งาน:** เหมาะสำหรับการ automate การวิเคราะห์ PE, การสกัดข้อมูล, หรือการสร้างเครื่องมือ PE analysis ของตัวเอง

7.  **LIEF (Library to Instrument Executable Formats):**
    *   **ประเภท:** Open-source C++/Python library
    *   **จุดเด่น:** รองรับหลาย executable formats (PE, ELF, Mach-O), มี API ที่ทันสมัยสำหรับการ parse, modify, และ build PE files
    *   **การใช้งาน:** คล้าย `pefile` แต่รองรับ format อื่นๆ ด้วย และมี feature ที่ advance กว่าในบางด้าน

## 20.2 Disassemblers และ Decompilers

เครื่องมือกลุ่มนี้ใช้ในการแปลง machine code กลับเป็น Assembly language (disassembly) หรือพยายามสร้าง source code ในภาษาระดับสูง (decompilation) เพื่อทำความเข้าใจการทำงานของโปรแกรม

1.  **IDA Pro (Interactive Disassembler):**
    *   **ประเภท:** Commercial disassembler/debugger (Windows, Linux, macOS)
    *   **จุดเด่น:** เป็นมาตรฐานอุตสาหกรรม, มีความสามารถสูงมากในการวิเคราะห์โค้ด, สร้าง control flow graphs, cross-references, มี scripting (IDC, IDAPython), และมี decompiler add-on (Hex-Rays Decompiler) ที่ทรงพลังมาก
    *   **การใช้งาน:** สำหรับการทำ reverse engineering เชิงลึกของมัลแวร์และซอฟต์แวร์ทั่วไป

2.  **Ghidra:**
    *   **ประเภท:** Open-source software reverse engineering (SRE) framework พัฒนาโดย NSA (Java-based, cross-platform)
    *   **จุดเด่น:** มี disassembler, decompiler (สำหรับหลายสถาปัตยกรรม), scripting (Java, Python), และเครื่องมือวิเคราะห์อื่นๆ ในตัว สามารถทำงานร่วมกันเป็นทีมได้ (multi-user repository)
    *   **การใช้งาน:** เป็นทางเลือก open source ที่ดีมากสำหรับ IDA Pro

3.  **Radare2 / Cutter:**
    *   **ประเภท:** Open-source reverse engineering framework (Radare2 เป็น command-line, Cutter เป็น GUI frontend) (cross-platform)
    *   **จุดเด่น:** มีความสามารถหลากหลาย (disassembly, debugging, hex editing, binary diffing), มี scripting, และ community ที่ active
    *   **การใช้งาน:** เหมาะสำหรับผู้ที่ชอบ command-line หรือต้องการเครื่องมือ open source ที่ยืดหยุ่น

4.  **Binary Ninja:**
    *   **ประเภท:** Commercial reverse engineering platform (cross-platform)
    *   **จุดเด่น:** User interface ที่ทันสมัย, มี intermediate languages (ILs) หลายระดับ, API ที่ดีสำหรับการ automate และเขียน plugin, มี decompiler (experimental)
    *   **การใช้งาน:** เป็นอีกทางเลือก commercial ที่น่าสนใจสำหรับ IDA Pro

5.  **dnSpy / ILSpy (สำหรับ .NET PE Files):**
    *   **ประเภท:** Open-source .NET decompiler and debugger (dnSpy), .NET decompiler (ILSpy) (Windows)
    *   **จุดเด่น:** สามารถ decompile .NET assemblies (MSIL code) กลับเป็น C# หรือ VB.NET ได้อย่างแม่นยำ dnSpy ยังมี debugger ในตัว
    *   **การใช้งาน:** จำเป็นอย่างยิ่งสำหรับการวิเคราะห์ .NET malware หรือ .NET applications

## 20.3 Debuggers

เครื่องมือกลุ่มนี้ใช้ในการรันโปรแกรมทีละขั้นตอน (step-by-step), ตรวจสอบค่า registers และ memory, ตั้ง breakpoints, และทำความเข้าใจพฤติกรรมการทำงานของโปรแกรมใน runtime

1.  **x64dbg / x32dbg:**
    *   **ประเภท:** Open-source user-mode debugger สำหรับ Windows (x64dbg สำหรับ 64-bit, x32dbg สำหรับ 32-bit)
    *   **จุดเด่น:** User interface ที่ใช้งานง่าย, มี plugin และ scripting (ผ่าน C++, Python), เป็นที่นิยมมากในหมู่นักวิเคราะห์มัลแวร์
    *   **การใช้งาน:** สำหรับ dynamic analysis, unpacking, และ RE

2.  **WinDbg (Windows Debugger):**
    *   **ประเภท:** Freeware debugger จาก Microsoft (Windows)
    *   **จุดเด่น:** ทรงพลังมาก, สามารถ debug ได้ทั้ง user-mode และ kernel-mode, มี command language ที่ซับซ้อน, ใช้ในการวิเคราะห์ crash dumps
    *   **การใช้งาน:** เหมาะสำหรับงาน RE ขั้นสูง, kernel debugging, และการวิเคราะห์ OS internals (อาจจะ learning curve สูงกว่าตัวอื่น)

3.  **OllyDbg (Version 1.10 และ 2.x):**
    *   **ประเภท:** Freeware user-mode debugger สำหรับ 32-bit Windows (เก่าแต่ยังคงมีคนใช้)
    *   **จุดเด่น:** User interface ที่เป็นมิตรกับผู้เริ่มต้น, มี plugin เยอะ
    *   **การใช้งาน:** สำหรับ dynamic analysis ของ 32-bit malware (ไม่รองรับ 64-bit)

4.  **Debuggers ในตัวของ IDA Pro, Ghidra, Radare2:**
    *   Disassembler/RE frameworks เหล่านี้มักจะมี debugger ในตัว ทำให้สามารถสลับระหว่าง static และ dynamic analysis ได้อย่างราบรื่น

## 20.4 String Extractors และ Entropy Analyzers

1.  **`strings` (Sysinternals/Linux):**
    *   **ประเภท:** Command-line tool
    *   **การใช้งาน:** ดึง ASCII/Unicode strings จากไฟล์

2.  **FLOSS (FireEye Labs Obfuscated String Solver):**
    *   **ประเภท:** Open-source Python tool
    *   **การใช้งาน:** พยายาม decode/deobfuscate strings ที่ถูกซ่อนด้วยเทคนิคทั่วไป (เช่น stack strings, XORed strings) โดยใช้ static analysis และ emulation

3.  **`binwalk`:**
    *   **ประเภท:** Open-source firmware analysis tool (Linux, macOS)
    *   **การใช้งาน:** มี option `-E` สำหรับคำนวณและแสดง entropy plot ของไฟล์ ซึ่งช่วยในการหาข้อมูลที่ถูกบีบอัด/เข้ารหัส

## 20.5 Packer Identifiers และ Unpackers

1.  **PEiD (เก่าแต่ยังใช้ในการอ้างอิง):**
    *   **ประเภท:** Freeware packer/compiler identifier (Windows)
    *   **การใช้งาน:** ใช้ signature database ในการระบุว่า PE file ถูก pack ด้วย packer หรือ compile ด้วย compiler ใด (ไม่ค่อยอัปเดตแล้ว)

2.  **Detect It Easy (DIE):**
    *   **ประเภท:** Open-source packer/compiler/protector identifier (Windows, Linux, macOS)
    *   **การใช้งาน:** ทันสมัยกว่า PEiD, มี signature database ที่ใหญ่กว่า, มี scripting, และสามารถแสดง entropy ได้
    *   **ข้อควรระวัง:** การระบุ packer ไม่ได้หมายความว่าจะ unpack ได้เสมอไป

3.  **UPX (Ultimate Packer for eXecutables):**
    *   **ประเภท:** Open-source packer (command-line)
    *   **การใช้งาน:** นอกจากจะใช้ pack แล้ว ยังมี option `-d` (decompress) สำหรับ unpack ไฟล์ที่ถูก pack ด้วย UPX (ถ้าไม่ได้ถูก modified)

4.  **Manual Unpacking Tools (Plugins/Scripts for Debuggers):**
    *   **Scylla:** Plugin สำหรับ x64dbg/OllyDbg ที่ช่วยในการ dump process memory และ rebuild IAT
    *   **ImpREC (Import Reconstructor):** เครื่องมือเก่าที่ช่วย rebuild IAT จาก process dump
    *   Scripts ต่างๆ ที่ช่วย automate บางส่วนของการ manual unpacking

## 20.6 Memory Forensics Tools (ที่เกี่ยวข้องกับ PE Analysis)

1.  **Volatility Framework / Volatility 3:**
    *   **ประเภท:** Open-source memory forensics framework (Python)
    *   **การใช้งาน:** สามารถวิเคราะห์ memory dumps (RAM dumps) เพื่อ:
        *   แสดงรายการ process และ DLLs ที่โหลด (`pslist`, `dlllist`, `ldrmodules`)
        *   Dump PE images (modules, drivers) จาก memory (`procdump`, `moddump`)
        *   ตรวจจับ code injection, IAT/EAT hooking, hidden modules (`malfind`, `apihooks`, `ssdt`)
        *   วิเคราะห์ PEB, TEB, kernel objects

2.  **Rekall Memory Forensic Framework:**
    *   **ประเภท:** Open-source memory forensics framework (Python) (พัฒนาแยกจาก Volatility)
    *   **การใช้งาน:** คล้าย Volatility มี plugin สำหรับวิเคราะห์ PE-related artifacts ใน memory

## 20.7 Online Analysis Platforms

1.  **VirusTotal (VT):**
    *   **ประเภท:** Online malware scanning service
    *   **การใช้งาน:** Upload ไฟล์หรือ hash เพื่อดูผลการ scan จาก AV engines จำนวนมาก, ดูข้อมูล PE structure เบื้องต้น, strings, imports/exports, community comments, และ sandbox reports (ถ้ามี)
    *   **ข้อควรระวัง:** การ upload ไฟล์ที่เป็นความลับ/อ่อนไหว อาจทำให้ข้อมูลรั่วไหล

2.  **Hybrid Analysis / Any.Run / Joe Sandbox / Hatching Triage:**
    *   **ประเภท:** Online sandboxing services (บางตัวมี free tier)
    *   **การใช้งาน:** รัน PE file ใน controlled environment และดูพฤติกรรม (network, file, registry, process activity), IOCs, screenshots, และบางครั้งก็มี unpacked sample ให้ download
    *   **ข้อควรระวัง:** เหมือน VirusTotal เรื่องการ upload ไฟล์

## 20.8 การเลือกใช้เครื่องมือ

*   **เริ่มต้นด้วย PE Viewer:** สำหรับ static analysis เบื้องต้น Pestudio, CFF Explorer, หรือ PE-bear เป็นตัวเลือกที่ดี
*   **ถ้าสงสัยว่า Packed/Obfuscated:** ใช้ DIE หรือดู entropy ถ้าเป็น packer ที่รู้จัก อาจลองใช้ unpacker เฉพาะ (เช่น UPX -d) หรือเตรียมทำ manual unpacking ด้วย debugger
*   **สำหรับการ Reverse Engineering:** IDA Pro, Ghidra, หรือ Radare2/Cutter เป็นเครื่องมือหลัก
*   **สำหรับการ Dynamic Analysis:** x64dbg/x32dbg หรือ WinDbg
*   **สำหรับการ Automate:** Python กับ `pefile` หรือ LIEF
*   **สำหรับการวิเคราะห์ .NET:** dnSpy หรือ ILSpy
*   **สำหรับการวิเคราะห์ Memory Dumps:** Volatility หรือ Rekall

**คำแนะนำ:**
*   **เรียนรู้หลายๆ เครื่องมือ:** แต่ละเครื่องมือมีจุดแข็งจุดอ่อนต่างกัน
*   **ฝึกฝน:** การใช้เครื่องมือเหล่านี้ให้คล่องแคล่วต้องอาศัยการฝึกฝนกับ PE files จริง (ทั้ง benign และ malicious)
*   **เข้าใจพื้นฐาน PE Format ก่อน:** การใช้เครื่องมือจะมีประสิทธิภาพมากขึ้นถ้าเข้าใจว่าข้อมูลที่เครื่องมือแสดงนั้นหมายถึงอะไรใน PE structure

## 20.9 สรุป

มีเครื่องมือมากมายที่ช่วยในการวิเคราะห์ PE file ตั้งแต่ PE viewer ง่ายๆ ไปจนถึง RE framework ที่ซับซ้อน และ memory forensics tools การเลือกใช้เครื่องมือที่เหมาะสมกับงานและมีความเข้าใจในข้อมูลที่เครื่องมือเหล่านั้นแสดงผล (ซึ่งต้องอาศัยความรู้เรื่อง PE format) เป็นสิ่งสำคัญอย่างยิ่งสำหรับนักวิเคราะห์ Cybersecurity ในการตรวจจับ, ทำความเข้าใจ, และรับมือกับภัยคุกคามที่เกี่ยวข้องกับ PE file

ในส่วนสุดท้ายของหนังสือ เราจะมาดูหัวข้อขั้นสูงบางประการ และสรุปภาพรวมของรายวิชานี้
