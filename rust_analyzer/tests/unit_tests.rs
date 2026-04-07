use rust_analyzer::{disassembler::ForensicDisassembler, yara_parser::YaraLiteEngine, config::EngineConfig};

#[test]
fn test_disasm_ret() {
    let disasm = ForensicDisassembler::new();
    let data = vec![0xC3]; // RET
    let insns = disasm.disassemble(&data, 0x1000);
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].mnemonic, "RET");
}

#[test]
fn test_disasm_jmp_rel8() {
    let disasm = ForensicDisassembler::new();
    let data = vec![0xEB, 0xFE]; // JMP -2 (infinite loop)
    let insns = disasm.disassemble(&data, 0x0);
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].mnemonic, "JMP rel8");
}

#[test]
fn test_disasm_call() {
    let disasm = ForensicDisassembler::new();
    let data = vec![0xE8, 0x00, 0x00, 0x00, 0x00]; 
    let insns = disasm.disassemble(&data, 0x100);
    assert!(insns[0].mnemonic.contains("CALL"));
}

#[test]
fn test_yara_blacklotus_matching() {
    let mut engine = YaraLiteEngine::new();
    engine.add_rule(YaraLiteEngine::get_blacklotus_rule());
    let data = vec![0x48, 0x83, 0xEC, 0x28, 0xE8]; // sc_loader pattern
    let hits = engine.scan(&data);
    assert!(hits.iter().any(|h| h.contains("BlackLotus")));
}

#[test]
fn test_config_json_roundtrip() {
    let config = EngineConfig::default();
    let json = config.to_json();
    let parsed = EngineConfig::from_json(&json).unwrap();
    assert_eq!(parsed.parser.entropy_threshold, 7.2);
}
#[test]
fn test_disasm_xor() {
    let disasm = ForensicDisassembler::new();
    let data = vec![0x31, 0xC0]; // XOR EAX, EAX
    let insns = disasm.disassemble(&data, 0x0);
    assert_eq!(insns[0].mnemonic, "XOR reg/mem");
}

#[test]
fn test_disasm_stack() {
    let disasm = ForensicDisassembler::new();
    let data = vec![0x50, 0x58]; // PUSH EAX, POP EAX
    let insns = disasm.disassemble(&data, 0x0);
    assert_eq!(insns.len(), 2);
    assert_eq!(insns[0].mnemonic, "PUSH reg (0x50)");
    assert_eq!(insns[1].mnemonic, "POP reg (0x58)");
}

#[test]
fn test_yara_multi_rule() {
    let mut engine = YaraLiteEngine::new();
    engine.add_rule(YaraLiteEngine::get_blacklotus_rule());
    engine.add_rule(YaraLiteEngine::get_cosmicstrand_rule());
    
    let data = vec![0x4D, 0x6F, 0x6B, 0x4C, 0x69, 0x73, 0x74]; // MokList
    let hits = engine.scan(&data);
    assert!(hits.len() >= 1);
}
