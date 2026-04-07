use rust_analyzer::{NvramScanner, UefiVariable, disassembler::ForensicDisassembler};

#[test]
fn test_mock_nvram_high_density() {
    let mut vars = Vec::new();
    for i in 0..50 {
        vars.push(UefiVariable {
            name: format!("Boot{}", i),
            guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c".to_string(),
            attributes: 7,
            data_size: 16,
            data_sha256: "hash".to_string(),
        });
    }
    
    let scanner = NvramScanner::new();
    let hits = scanner.scan_variables(&vars);
    assert_eq!(hits.len(), 0); // All standard
}

#[test]
fn test_moklist_corruption() {
    let var = UefiVariable {
        name: "MokListTrusted".to_string(),
        guid: "605dab50-e046-4300-abb9-72901307ebb1".to_string(),
        attributes: 7,
        data_size: 9999, // Over the 4096 limit
        data_sha256: "corrupted_hash".to_string(),
    };
    
    let scanner = NvramScanner::new();
    let hits = scanner.scan_variables(&[var]);
    assert!(!hits.is_empty());
}

#[test]
fn test_disasm_indirect_jump() {
    let disasm = ForensicDisassembler::new();
    let data = vec![0xFF, 0x20]; // JMP [RAX]
    let insns = disasm.disassemble(&data, 0x0);
    assert_eq!(insns[0].mnemonic, "JMP reg/mem");
}
