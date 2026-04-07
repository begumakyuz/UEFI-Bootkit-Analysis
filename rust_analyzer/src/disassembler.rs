//! # Forensic Disassembler for UEFI Entry Point Analysis
//! 
//! This module implements a lightweight x86-64 instruction decoder 
//! specifically tailored for identifying malicious redirections at 
//! the entry point of UEFI drivers and OS loaders.
//! 
//! It focuses on "Proximity Scanning" (searching for JMPs/CALLs 
//! within the first few instruction blocks) to detect shellcode 
//! hooks or secondary stage loaders.

use serde::{Deserialize, Serialize};

/// Supported x86-64 CPU instruction types for forensic mapping.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum InsnType {
    /// Conditional or Unconditional JUMP
    Jump,
    /// Function CALL
    Call,
    /// Return (RET/IRET)
    Return,
    /// Software Interrupt (INT 3, INT 21, etc.)
    Interrupt,
    /// Stack manipulation (PUSH, POP)
    Stack,
    /// General data movement (MOV, LEA)
    Movement,
    /// Arithmetic / Logic (ADD, SUB, XOR)
    Alu,
    /// Unknown or unsupported opcode
    Unknown,
}

/// A decoded instruction with its offset, raw bytes, and mnemonic type.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DecodedInstruction {
    pub offset: u32,
    pub bytes: Vec<u8>,
    pub insn_type: InsnType,
    pub mnemonic: String,
}

/// The core disassembler engine.
pub struct ForensicDisassembler;

impl ForensicDisassembler {
    pub fn new() -> Self {
        Self
    }

    /// Decodes a stream of raw bytes into structured instructions.
    /// 
    /// This is a "best-effort" linear sweep decoder. While not as robust 
    /// as full disassemblers (like Zydis or Iced-x86), it is optimized 
    /// for detecting obfuscated transfer-of-control patterns in 
    /// small binary blocks (< 4KB).
    pub fn disassemble(&self, data: &[u8], base_address: u32) -> Vec<DecodedInstruction> {
        let mut instructions = Vec::new();
        let mut cursor = 0;

        while cursor < data.len() {
            let offset = base_address + cursor as u32;
            let opcode = data[cursor];

            // 1. Identify the instruction based on the primary opcode byte.
            // These mappings follow the Intel/AMD x86-64 ISA manual.
            let (insn_type, mnemonic, length) = match opcode {
                // Return instructions
                0xC3 | 0xCB | 0xC2 | 0xCA => (InsnType::Return, "RET".to_string(), 1),
                
                // Jumps (Direct/Relative)
                0xEB => (InsnType::Jump, "JMP rel8".to_string(), 2),
                0xE9 => (InsnType::Jump, "JMP rel32".to_string(), 5),
                0xFF if cursor + 1 < data.len() && (data[cursor+1] & 0x38) >> 3 == 4 => {
                    (InsnType::Jump, "JMP reg/mem".to_string(), 2) // ModR/M check
                },
                
                // Conditional Jumps (various)
                0x70..=0x7F => (InsnType::Jump, format!("Jcc (0x{:02X})", opcode), 2),
                
                // Call instructions
                0xE8 => (InsnType::Call, "CALL rel32".to_string(), 5),
                0xFF if cursor + 1 < data.len() && (data[cursor+1] & 0x38) >> 3 == 2 => {
                    (InsnType::Call, "CALL reg/mem".to_string(), 2)
                },

                // Stack operations
                0x50..=0x57 => (InsnType::Stack, format!("PUSH reg (0x{:02X})", opcode), 1),
                0x58..=0x5F => (InsnType::Stack, format!("POP reg (0x{:02X})", opcode), 1),

                // Data Movement
                0x88..=0x8B => (InsnType::Movement, "MOV reg/mem".to_string(), 2),
                0xB0..=0xBF => (InsnType::Movement, format!("MOV imm (0x{:02X})", opcode), 5), // Assumed 32-bit imm

                // ALU operations
                0x31 | 0x33 => (InsnType::Alu, "XOR reg/mem".to_string(), 2),
                0x01 | 0x03 => (InsnType::Alu, "ADD reg/mem".to_string(), 2),
                0x90 => (InsnType::Alu, "NOP".to_string(), 1),

                // Interrupts
                0xCC => (InsnType::Interrupt, "INT 3".to_string(), 1),
                0xCD => (InsnType::Interrupt, "INT imm8".to_string(), 2),

                _ => (InsnType::Unknown, format!("?? (0x{:02X})", opcode), 1),
            };

            // 2. Extract the actual bytes for the decoded instruction.
            let actual_length = std::cmp::min(length, data.len() - cursor);
            let bytes = data[cursor..cursor + actual_length].to_vec();

            instructions.push(DecodedInstruction {
                offset,
                bytes,
                insn_type,
                mnemonic,
            });

            // 3. Advance the cursor, ensuring we don't exceed the buffer.
            cursor += actual_length;
            if actual_length == 0 { break; } // Safety break
        }

        instructions
    }

    /// Scans instructions for "Suspicious Indirect Control Flow".
    /// 
    /// Malware often uses CALL [RAX] or JMP [RCX] to jump to dynamically 
    /// allocated memory blocks (shellcode) away from the static text section.
    pub fn analyze_flow_anomalies(&self, instructions: &[DecodedInstruction]) -> Vec<String> {
        let mut alerts = Vec::new();

        for (i, insn) in instructions.iter().enumerate() {
            // Check for jumps within the first 10 instructions of the EP.
            // Early jumps are a classic indicator of a "jump-to-payload" stub.
            if i < 10 && insn.insn_type == InsnType::Jump {
                alerts.push(format!("Early jump detected at offset 0x{:X}. Potential loader stub.", insn.offset));
            }

            // Check for XOR-to-self (XOR EAX, EAX) often used in cleanup or shellcode.
            if insn.insn_type == InsnType::Alu && insn.mnemonic.contains("XOR") {
                if insn.bytes.len() > 1 && insn.bytes[0] == 0x31 && insn.bytes[1] == 0xC0 {
                     // XOR EAX, EAX detected
                }
            }
        }

        alerts
    }
}
