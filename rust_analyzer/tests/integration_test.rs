use rust_analyzer::{analyze_pe_file, analyze_elf_file};

#[test]
fn test_pe_analysis_fail_on_invalid_path() {
    let result = analyze_pe_file("non_existent_file.efi");
    assert!(result.is_err());
}

#[test]
fn test_elf_analysis_fail_on_invalid_path() {
    let result = analyze_elf_file("non_existent_file.elf");
    assert!(result.is_err());
}

// Note: Real binary testing would require sample files which are managed 
// in the /assets/ directory of the repository.
#[test]
fn test_security_logic_integration() {
    // Ensuring the modular architecture correctly handles error propagation
    let path = "Cargo.toml"; // Not a PE file
    let result = analyze_pe_file(path);
    match result {
        Err(e) => println!("Correctly failed PE parse: {}", e),
        _ => panic!("Should have failed to parse Cargo.toml as PE"),
    }
}
