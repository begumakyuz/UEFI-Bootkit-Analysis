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
fn test_disasm_early_jump_alert() {
    let disasm = ForensicDisassembler::new();
    let data = vec![0xEB, 0x01, 0x90]; // JMP 1, NOP
    let insns = disasm.disassemble(&data, 0x0);
    let alerts = disasm.analyze_flow_anomalies(&insns);
    assert!(!alerts.is_empty());
}
