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

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let data = vec![0x00; 1024];
        let entropy = calculate_shannon_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_high_entropy() {
        // Random distribution usually gives high entropy
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_shannon_entropy(&data);
        assert!(entropy > 7.9 && entropy <= 8.0);
    }
}
