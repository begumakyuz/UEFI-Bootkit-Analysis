import idc
import idaapi
import idautils

def resolve_efi_boot_services():
    """
    IDA Pro script to find and rename EFI_BOOT_SERVICES calls in UEFI Bootkits.
    This script searches for typical gBS pattern usages and names them to aid in reverse engineering.
    """
    print("[*] Starting EFI_BOOT_SERVICES (gBS) resolution script...")
    
    # In UEFI PE32+ binaries, gBS is often stored in a global variable pointing to the EFI_BOOT_SERVICES table
    # Standard signature for LocateProtocol: 0x48 0x8B 0x... (lea rcx, [guid]) followed by call [rax+0x140]
    
    # As a simple heuristic for documentation purposes, we look for CALL [reg+offset]
    # where offset matches known EFI_BOOT_SERVICES offsets.
    
    efi_funcs = {
        0x10: "gBS_RaiseTPL",
        0x18: "gBS_RestoreTPL",
        0x20: "gBS_AllocatePages",
        0x28: "gBS_FreePages",
        0x30: "gBS_GetMemoryMap",
        0x38: "gBS_AllocatePool",
        0x40: "gBS_FreePool",
        0x48: "gBS_CreateEvent",
        0x50: "gBS_SetTimer",
        0x80: "gBS_InstallProtocolInterface",
        0x88: "gBS_ReinstallProtocolInterface",
        0x90: "gBS_UninstallProtocolInterface",
        0x98: "gBS_HandleProtocol",
        0x140: "gBS_LocateProtocol",
        0x118: "gBS_CopyMem",
        0x120: "gBS_SetMem"
    }
    
    count = 0
    for funcAddress in idautils.Functions():
        for head in idautils.FuncItems(funcAddress):
            mnem = idc.print_insn_mnem(head)
            if mnem == "call":
                opnd = idc.print_operand(head, 0)
                # Check for forms like [rax+140h] or [rcx+38h]
                if "[" in opnd and "h]" in opnd:
                    try:
                        # Extract the hex offset
                        offset_str = opnd.split("+")[1].split("h")[0]
                        offset = int(offset_str, 16)
                        if offset in efi_funcs:
                            idc.set_cmt(head, f"-> {efi_funcs[offset]}", 0)
                            count += 1
                    except Exception:
                        pass
                        
    print(f"[+] Script finished. Resolved and commented {count} potential gBS calls.")

if __name__ == "__main__":
    resolve_efi_boot_services()
