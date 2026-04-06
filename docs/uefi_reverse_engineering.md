# UEFI Bootkit Reverse Engineering: Ring-2 Evasion Analysis

**Author:** Begüm AKYÜZ  
**Affiliation:** İstinye University - Information Security Technology  
**Date:** April 2026  

## Executive Summary
This document provides a deep-dive analysis into the **BlackLotus UEFI Bootkit**, focusing on its ability to bypass **PRM (Platform Runtime Mechanism)** and **HVCI (Hypervisor-Protected Code Integrity)**. By operating at **Ring-2 (System Management Mode / SMM)** and the pre-OS stage, these threats remain invisible to traditional kernel-mode (Ring-0) EDRs.

---

## 1. Boot Sequence Hooking Mechanisms

### 1.1 `ExitBootServices` (EBS) Hijacking
BlackLotus relies on intercepting the `ExitBootServices` call to gain persistence before the OS loader (`winload.efi`) takes over.
*   **Vector:** The bootkit modifies the `EFI_BOOT_SERVICES` table in memory.
*   **Hook Point:** `gBS->ExitBootServices`.
*   **Purpose:** To patch the Windows kernel memory in transition, specifically targeting `ntoskrnl.exe` validation checks.

### 1.2 `SetVirtualAddressMap` Manipulation
By hooking `SetVirtualAddressMap`, the malware ensures its own memory space is mapped correctly into the OS address space, allowing for persistent communication between the firmware and the OS.

---

## 2. Evasion Analysis (Ring-2 Bypass)

### 2.1 Bypassing HVCI
The bootkit achieves HVCI bypass by loading its own malicious drivers before the hypervisor is fully initialized.
1.  **Stage 1:** Execute in UEFI environment.
2.  **Stage 2:** Patch `skci.dll` (Secure Kernel Code Integrity) in memory.
3.  **Stage 3:** Set `testsigning` to ON or bypass certificate checks via BCD manipulation.

### 2.2 SMM (Ring -2) Implications
BlackLotus effectively sits below the OS. Even if the OS is reinstalled, the infection persists in the **EFI System Partition (ESP)** or, in theoretical extremists, the **SPI Flash**. Our `rust_analyzer` targets the ESP version by detecting high-entropy segments in `bootmgfw.efi` and `winload.efi`.

---

## 3. Forensic Detection Logic

To detect such "Living-off-the-Firmware" (LOTF) attacks, we employ:
1.  **Shannon Entropy:** Identifying packed/encrypted payloads in standard EFI binaries.
2.  **IAT Correlation:** Searching for `LocateProtocol` and `OpenProtocol` calls in binaries that shouldn't have them.
3.  **Signature Match:** YARA rules targeting the `HvciDxe` string and the `\\BlackLotus\\` PDB path.

---

## 4. Conclusion
UEFI security cannot rely solely on **Secure Boot**. If the **DB/DBX** revocation list is outdated (as in the Baton Drop vulnerability), binaries signed by old, compromised certificates will still execute. Defense-in-depth requires firmware-level static analysis and rootless containerization for security tool deployment.
