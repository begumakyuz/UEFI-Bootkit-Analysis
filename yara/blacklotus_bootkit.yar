rule BlackLotus_UEFI_Bootkit {
    meta:
        author = "Güvenlik Uzmanı / Sistem Mimarı"
        description = "BlackLotus UEFI Bootkit tespit kuralı. Baton Drop (CVE-2022-21894) zafiyetine ve bilinen payload stringlerine odaklanır."
        date = "2026-04-03"
        reference = "ESET - BlackLotus UEFI Bootkit: Myth Confirmed"
        target_entity = "EFI System Partition / PE32+ UEFI binaries"

    strings:
        // Zararlının ESP'ye attığı veya komuta kontrol (C2) için kullandığı stringler
        $s1 = "system32\\winload.efi" wide ascii
        $s2 = "bootmgfw.efi" wide ascii
        $s3 = "HvciDxe" wide ascii
        $s4 = "API-MS-WIN-" wide ascii
        
        // PDB Yolu Kısımları (Genelde derleyici tarafından eklenen path kalıntıları)
        $pdb1 = "\\BlackLotus\\" ascii
        $pdb2 = "bootkit.pdb" ascii

        // Bypass ve hooking işlemleri için kullanılan UEFI Hex patternleri
        // OslArchTransferToKernel veya ImgArchStartBootApplication override patternleri
        $hook_pattern_1 = { 48 8B C4 48 89 58 10 48 89 70 18 48 89 78 20 55 41 54 41 55 41 56 41 57 48 8D 68 A1 48 81 EC 50 00 00 00 }
        
        // BCD Edit stringleri (Bitlocker ve HVCI kapatma)
        $bcd1 = "bcdedit /set {default} testsigning on" wide ascii
        $bcd2 = "bcdedit /set {default} nointegritychecks on" wide ascii

    condition:
        uint16(0) == 0x5a4d and // PE File (MZ)
        filesize < 2MB and
        (
            2 of ($s*) or
            any of ($pdb*) or
            $hook_pattern_1 or
            any of ($bcd*)
        )
}
