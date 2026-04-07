use std::collections::HashMap;

/// Calculates the Shannon Entropy of a given byte slice.
///
/// # Mathematical Mathematical Foundation
/// Shannon Entropy (H) measures the uncertainty or unpredictability of data.
/// For a string of bytes, it's calculated using the formula:
/// H = -Σ(p_i * log2(p_i))
/// where:
/// - p_i is the probability of a specific byte value (0-255) occurring in the data.
/// - log2(p_i) is the base-2 logarithm of that probability.
/// 
/// High entropy (approaching 8.0 for bytes) indicates highly random/compressed/encrypted data,
/// which is a strong heuristic for identifying packed executable sections (e.g., UPX, Themida).
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_counts = HashMap::new();
    let data_len = data.len() as f64;

    // Count occurrences of each byte (0x00 to 0xFF)
    for &byte in data {
        *byte_counts.entry(byte).or_insert(0) += 1;
    }

    let mut entropy: f64 = 0.0;

    // Calculate probabilities and sum logarithmic values
    for &count in byte_counts.values() {
        let probability = (count as f64) / data_len;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    // TODO(Architect): Implement Chi-Square distribution check alongside Shannon entropy
    // for a more robust heuristic against advanced polymorphic engines.
    // TODO(Security): Cross-reference section entropy peaks with IAT count to dynamically
    // flag in-memory unpack loops (e.g. VirtualAlloc + memcpy signatures).

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let data = vec![0x00; 1024]; // Single repeating character = 0 entropy
        let entropy = calculate_shannon_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_perfect_entropy() {
        // A perfectly uniform distribution (0-255 once) should yield 8.0 entropy
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_shannon_entropy(&data);
        assert_eq!(entropy, 8.0);
    }

    #[test]
    fn test_malicious_simulation_entropy() {
        // Typical packed payload (simulated)
        let mut data = vec![0xCC; 100];
        data.extend(vec![0xAA; 100]);
        data.extend(vec![0xBB; 100]);
        let entropy = calculate_shannon_entropy(&data);
        // Should be approximately log2(3) = 1.58
        assert!(entropy > 1.5 && entropy < 1.6);
    }

    #[test]
    fn test_empty_buffer() {
        let data: Vec<u8> = vec![];
        let entropy = calculate_shannon_entropy(&data);
        assert_eq!(entropy, 0.0);
    }
}
