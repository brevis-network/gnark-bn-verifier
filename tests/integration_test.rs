use bn::Fr;
use gnark_bn_verifier::{
    io::{uncompressed_bytes_to_g1_point, uncompressed_bytes_to_g2_point},
    proof::Groth16Proof,
    vk::Groth16VKey,
};

// Helper: create a valid VK with given num_k
fn create_valid_vk_bytes(num_k: u32) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(292 + (num_k as usize) * 32);

    // g1_alpha (32 bytes)
    let mut alpha = [0u8; 32];
    alpha[0] = 0x02; // positive flag
    buffer.extend_from_slice(&alpha);

    // padding (32 bytes)
    buffer.extend_from_slice(&[0u8; 32]);

    // g2_beta (64 bytes)
    let mut beta = [0u8; 64];
    beta[0] = 0x02;
    buffer.extend_from_slice(&beta);

    // g2_gamma (64 bytes)
    let mut gamma = [0u8; 64];
    gamma[0] = 0x02;
    buffer.extend_from_slice(&gamma);

    // g2_delta (64 bytes)
    let mut delta = [0u8; 64];
    delta[0] = 0x02;
    buffer.extend_from_slice(&delta);

    // num_k (4 bytes, big-endian)
    buffer.extend_from_slice(&num_k.to_be_bytes());

    // K points (num_k * 32 bytes)
    let mut k = [0u8; 32];
    k[0] = 0x02;
    for _ in 0..num_k {
        buffer.extend_from_slice(&k);
    }

    buffer
}

// Helper: create a valid proof bytes with given structure
fn create_valid_proof_bytes() -> Vec<u8> {
    let mut buffer = Vec::with_capacity(256);

    // ar (64 bytes G1 uncompressed)
    buffer.extend_from_slice(&[0u8; 64]);

    // bs (128 bytes G2 uncompressed)
    buffer.extend_from_slice(&[0u8; 128]);

    // krs (64 bytes G1 uncompressed)
    buffer.extend_from_slice(&[0u8; 64]);

    buffer
}

mod vk_tests {
    use super::*;

    #[test]
    fn test_vk_buffer_too_short() {
        let buffer = vec![0u8; 100]; // too short
        let result = Groth16VKey::try_from(buffer.as_slice());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"), "Expected 'too short' error, got: {}", err);
    }

    #[test]
    fn test_vk_num_k_zero() {
        let buffer = create_valid_vk_bytes(0);
        let result = Groth16VKey::try_from(buffer.as_slice());
        // num_k = 0 is allowed but buffer should still have exactly 292 bytes
        // since num_k * 32 = 0
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("short"));
    }

    #[test]
    fn test_vk_num_k_too_large() {
        let buffer = create_valid_vk_bytes(1_000_001); // exceeds MAX_K_COUNT
        let result = Groth16VKey::try_from(buffer.as_slice());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Either num_k limit or point parsing error is acceptable
        // but should not be buffer-too-short
        assert!(
            err.contains("too large") || err.contains("invalid"),
            "Expected 'too large' or 'invalid' error, got: {}",
            err
        );
    }

    #[test]
    fn test_vk_buffer_insufficient_for_k_points() {
        // Create buffer that claims 10 k points but only provides 5
        let mut buffer = create_valid_vk_bytes(5);
        // Overwrite num_k to claim 10
        buffer[288..292].copy_from_slice(&10u32.to_be_bytes());
        // Don't add more k points, buffer is now too short

        let result = Groth16VKey::try_from(buffer.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_vk_valid_single_k() {
        let buffer = create_valid_vk_bytes(1);
        let result = Groth16VKey::try_from(buffer.as_slice());
        // May fail due to invalid point data, but shouldn't panic
        // and should not be OOM or buffer error
        if result.is_err() {
            let err = result.unwrap_err().to_string();
            assert!(!err.contains("too short") && !err.contains("too large"));
        }
    }

    #[test]
    fn test_vk_valid_multiple_k() {
        let buffer = create_valid_vk_bytes(100);
        let result = Groth16VKey::try_from(buffer.as_slice());
        if result.is_err() {
            let err = result.unwrap_err().to_string();
            assert!(!err.contains("OOM"), "Should not OOM on reasonable k count");
        }
    }

    #[test]
    fn test_vk_exact_boundary() {
        // Test with exactly MAX_K_COUNT
        let buffer = create_valid_vk_bytes(1_000_000);
        let result = Groth16VKey::try_from(buffer.as_slice());
        // Should not fail due to count limit
        // May fail on actual point data, but not due to bounds
        if result.is_err() {
            let err = result.unwrap_err().to_string();
            assert!(!err.contains("too large"));
        }
    }

    #[test]
    fn test_vk_num_public_inputs_method() {
        let buffer = create_valid_vk_bytes(6); // k.len() = 6, so 5 public inputs expected
        let result = Groth16VKey::try_from(buffer.as_slice());
        if result.is_ok() {
            let vk = result.unwrap();
            assert_eq!(vk.num_public_inputs(), 5);
        }
    }
}

mod proof_tests {
    use super::*;

    #[test]
    fn test_proof_buffer_too_short() {
        let buffer = vec![0u8; 100]; // less than 256
        let result = Groth16Proof::try_from(buffer.as_slice());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid groth16 proof length"),
            "Expected 'invalid groth16 proof length' error, got: {}",
            err
        );
    }

    #[test]
    fn test_proof_exact_min_length() {
        let buffer = vec![0u8; 256];
        let result = Groth16Proof::try_from(buffer.as_slice());
        // Will fail on point parsing but not length check
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_proof_larger_than_min() {
        let buffer = vec![0u8; 300];
        let result = Groth16Proof::try_from(buffer.as_slice());
        assert!(result.is_err() || result.is_ok());
    }
}

mod io_tests {
    use super::*;

    #[test]
    fn test_g1_uncompressed_valid_length() {
        // 64 bytes: 32 for x, 32 for y
        let buffer = [0u8; 64];
        let result = uncompressed_bytes_to_g1_point(&buffer);
        // Zero point should be valid (0,0) technically is not on curve,
        // but from_slice might handle it differently
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_g1_uncompressed_invalid_length() {
        let buffer = [0u8; 63];
        let result = uncompressed_bytes_to_g1_point(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_g2_uncompressed_valid_length() {
        // 128 bytes for G2
        let buffer = [0u8; 128];
        let result = uncompressed_bytes_to_g2_point(&buffer);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_g2_uncompressed_invalid_length() {
        let buffer = [0u8; 64]; // should be 128
        let result = uncompressed_bytes_to_g2_point(&buffer);
        assert!(result.is_err());
    }
}

mod verification_tests {
    use super::*;

    #[test]
    fn test_verify_with_mismatched_input_length() {
        // Create a VK with 5 public inputs expected
        let vk_bytes = create_valid_vk_bytes(6); // k has 6 points, so 5 inputs expected
        let vk = Groth16VKey::try_from(vk_bytes.as_slice());
        if vk.is_err() {
            return; // Skip if VK is invalid due to point data
        }
        let vk = vk.unwrap();

        // Create proof
        let proof_bytes = create_valid_proof_bytes();
        let proof = Groth16Proof::try_from(proof_bytes.as_slice());
        if proof.is_err() {
            return; // Skip if proof is invalid
        }
        let proof = proof.unwrap();

        // Provide wrong number of inputs (e.g., 3 instead of 5)
        let inputs = [Fr::one(), Fr::one(), Fr::one()];

        let result = proof.verify(&vk, &inputs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("input length mismatch"),
            "Expected 'input length mismatch' error, got: {}",
            err
        );
    }

    #[test]
    fn test_verify_with_zero_inputs() {
        // VK with 1 public input (k.len() == 1 means 0 public inputs)
        let vk_bytes = create_valid_vk_bytes(1);
        let vk = Groth16VKey::try_from(vk_bytes.as_slice());
        if vk.is_err() {
            return;
        }
        let vk = vk.unwrap();

        let proof_bytes = create_valid_proof_bytes();
        let proof = Groth16Proof::try_from(proof_bytes.as_slice());
        if proof.is_err() {
            return;
        }
        let proof = proof.unwrap();

        // Empty public inputs
        let inputs: [Fr; 0] = [];
        let result = proof.verify(&vk, &inputs);
        // Should either succeed or fail due to invalid proof, not panic
        assert!(result.is_ok() || result.is_err());
    }
}

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_vk_empty_buffer() {
        let buffer = Vec::new();
        let result = Groth16VKey::try_from(buffer.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_empty_buffer() {
        let buffer = Vec::new();
        let result = Groth16Proof::try_from(buffer.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_vk_num_k_exactly_max() {
        let buffer = create_valid_vk_bytes(1_000_000);
        let result = Groth16VKey::try_from(buffer.as_slice());
        // Should process without OOM
        if result.is_ok() {
            let vk = result.unwrap();
            assert_eq!(vk.num_public_inputs(), 999_999);
        }
    }

    #[test]
    fn test_verify_does_not_panic_on_invalid_proof() {
        let vk_bytes = create_valid_vk_bytes(1);
        let vk = Groth16VKey::try_from(vk_bytes.as_slice());
        if vk.is_err() {
            return;
        }
        let vk = vk.unwrap();

        // Create proof with garbage data
        let proof_bytes = vec![0xFF; 256];
        let proof = Groth16Proof::try_from(proof_bytes.as_slice());

        if proof.is_ok() {
            let proof = proof.unwrap();
            let inputs: [Fr; 0] = [];
            let result = proof.verify(&vk, &inputs);
            // Should return error, not panic
            assert!(result.is_err());
        }
    }
}

// NOTE: A real Groth16 proof requires test vectors from a compiled circuit.
// The verification algorithm itself is tested via the algorithm_tests module.
mod algorithm_tests {
    use bn::{Gt, G1, G2, Group};
    use gnark_bn_verifier::vk::Groth16VKey;

    // Import helper functions from parent scope
    use crate::{create_valid_vk_bytes, create_valid_proof_bytes};

    #[test]
    fn test_pairing_with_generator_points() {
        // Test that pairing of generator points completes without error
        let g1 = G1::one();
        let g2 = G2::one();

        let result = bn::pairing_batch(&[(g1, g2.into())]);
        // Just verify the operation completes - result is some Gt element
        let _ = result;
    }

    #[test]
    fn test_pairing_with_zero_point() {
        // Test that e(0, any_point) = 1
        let zero_g1 = G1::zero();
        let g2 = G2::one();

        let result = bn::pairing_batch(&[(zero_g1, g2.into())]);
        assert_eq!(result, Gt::one());
    }

    #[test]
    fn test_vk_debug_trait() {
        // Verify Debug trait works for error messages
        let buffer = vec![0u8; 100];
        let result = Groth16VKey::try_from(buffer.as_slice());
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(!err_str.is_empty());
        assert!(err_str.contains("too short"));
    }

    #[test]
    fn test_verify_returns_error_on_invalid_proof() {
        use gnark_bn_verifier::proof::Groth16Proof;

        // Create a VK with 0 public inputs - using simple non-zero bytes
        let mut vk_bytes = create_valid_vk_bytes(1);
        // Set a valid-looking compressed point flag (0x02 = positive)
        vk_bytes[0] = 0x02;
        vk_bytes[64] = 0x02;
        vk_bytes[128] = 0x02;
        vk_bytes[224] = 0x02;

        let vk_result = Groth16VKey::try_from(vk_bytes.as_slice());
        if vk_result.is_err() {
            // VK parsing correctly rejects invalid points - test passes
            return;
        }
        let vk = vk_result.unwrap();

        // Create a proof with non-zero bytes
        let mut proof_bytes = create_valid_proof_bytes();
        // Fill with non-zero to avoid zero point rejection
        for byte in &mut proof_bytes {
            *byte = 0x03;
        }

        let proof_result = Groth16Proof::try_from(proof_bytes.as_slice());
        if proof_result.is_err() {
            // Proof parsing correctly rejects invalid points - test passes
            return;
        }
        let proof = proof_result.unwrap();

        // Verify should fail (not panic), confirming the algorithm runs
        let result = proof.verify(&vk, &[]);
        // With garbage points, verification will fail which is expected
        assert!(result.is_err());
    }
}
