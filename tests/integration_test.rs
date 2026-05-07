use bn::{AffineG1, AffineG2, Fq, Fr, Group, Gt, G1, G2};
use gnark_bn_verifier::{
    io::{
        unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point,
        uncompressed_bytes_to_g1_point, uncompressed_bytes_to_g2_point,
    },
    proof::Groth16Proof,
    vk::Groth16VKey,
};

const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;

fn fq_to_bytes(fq: Fq) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fq.to_big_endian(&mut bytes).unwrap();
    bytes
}

fn compressed_g1(point: AffineG1) -> [u8; 32] {
    let mut bytes = fq_to_bytes(point.x());
    bytes[0] |= if point.y() <= -point.y() {
        COMPRESSED_POSITIVE
    } else {
        COMPRESSED_NEGATIVE
    };
    bytes
}

fn compressed_g2(point: AffineG2) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    let x = point.x();
    bytes[..32].copy_from_slice(&fq_to_bytes(x.imaginary()));
    bytes[32..].copy_from_slice(&fq_to_bytes(x.real()));

    let (positive_y, negative_y) = AffineG2::get_ys_from_x_unchecked(x).unwrap();
    bytes[0] |= if point.y() == positive_y {
        COMPRESSED_POSITIVE
    } else {
        assert_eq!(point.y(), negative_y);
        COMPRESSED_NEGATIVE
    };
    bytes
}

fn uncompressed_g1(point: AffineG1) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&fq_to_bytes(point.x()));
    bytes[32..].copy_from_slice(&fq_to_bytes(point.y()));
    bytes
}

fn uncompressed_g2(point: AffineG2) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    let x = point.x();
    let y = point.y();
    bytes[..32].copy_from_slice(&fq_to_bytes(x.imaginary()));
    bytes[32..64].copy_from_slice(&fq_to_bytes(x.real()));
    bytes[64..96].copy_from_slice(&fq_to_bytes(y.imaginary()));
    bytes[96..].copy_from_slice(&fq_to_bytes(y.real()));
    bytes
}

fn vk_bytes_with_gamma(num_k: u32, gamma: AffineG2) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(292 + (num_k as usize) * 32);
    buffer.extend_from_slice(&compressed_g1(AffineG1::one()));
    buffer.extend_from_slice(&[0u8; 32]);
    buffer.extend_from_slice(&compressed_g2(AffineG2::one()));
    buffer.extend_from_slice(&compressed_g2(gamma));
    buffer.extend_from_slice(&[0u8; 32]);
    buffer.extend_from_slice(&compressed_g2(AffineG2::one()));
    buffer.extend_from_slice(&num_k.to_be_bytes());

    let k = compressed_g1(AffineG1::one());
    for _ in 0..num_k {
        buffer.extend_from_slice(&k);
    }

    buffer
}

fn vk_bytes(num_k: u32) -> Vec<u8> {
    vk_bytes_with_gamma(num_k, -AffineG2::one())
}

fn vk_header_with_num_k(num_k: u32) -> Vec<u8> {
    let mut buffer = vk_bytes(1);
    buffer.truncate(292);
    buffer[288..292].copy_from_slice(&num_k.to_be_bytes());
    buffer
}

fn proof_bytes() -> Vec<u8> {
    let mut buffer = Vec::with_capacity(256);
    buffer.extend_from_slice(&uncompressed_g1(AffineG1::one()));
    buffer.extend_from_slice(&uncompressed_g2(AffineG2::one()));
    buffer.extend_from_slice(&uncompressed_g1(AffineG1::one()));
    buffer
}

fn modulus_bytes_with_flag() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    Fq::modulus().to_big_endian(&mut bytes).unwrap();
    bytes[0] |= COMPRESSED_POSITIVE;
    bytes
}

mod vk_tests {
    use super::*;

    #[test]
    fn rejects_short_vk_buffer() {
        let err = Groth16VKey::try_from(vec![0u8; 100].as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains("too short"));
    }

    #[test]
    fn rejects_zero_k_count() {
        let err = Groth16VKey::try_from(vk_header_with_num_k(0).as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least 1"));
    }

    #[test]
    fn rejects_too_large_k_count_before_allocating_k_points() {
        let err = Groth16VKey::try_from(vk_header_with_num_k(1_000_001).as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains("too large"));
    }

    #[test]
    fn rejects_vk_with_missing_k_points() {
        let mut buffer = vk_bytes(2);
        buffer.truncate(buffer.len() - 32);
        let err = Groth16VKey::try_from(buffer.as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid vkey length"));
    }

    #[test]
    fn rejects_vk_with_trailing_bytes() {
        let mut buffer = vk_bytes(1);
        buffer.push(0);
        let err = Groth16VKey::try_from(buffer.as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid vkey length"));
    }

    #[test]
    fn parses_valid_vk_and_reports_public_input_count() {
        let vk = Groth16VKey::try_from(vk_bytes(6).as_slice()).unwrap();
        assert_eq!(vk.num_public_inputs(), 5);
    }
}

mod proof_tests {
    use super::*;

    #[test]
    fn rejects_short_proof_buffer() {
        let err = Groth16Proof::try_from(vec![0u8; 100].as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid groth16 proof length"));
    }

    #[test]
    fn rejects_proof_with_trailing_bytes() {
        let mut buffer = proof_bytes();
        buffer.push(0);
        let err = Groth16Proof::try_from(buffer.as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid groth16 proof length"));
    }

    #[test]
    fn parses_exact_length_proof() {
        Groth16Proof::try_from(proof_bytes().as_slice()).unwrap();
    }
}

mod io_tests {
    use super::*;

    #[test]
    fn parses_valid_compressed_g1_and_g2_points() {
        unchecked_compressed_x_to_g1_point(&compressed_g1(AffineG1::one())).unwrap();
        unchecked_compressed_x_to_g2_point(&compressed_g2(AffineG2::one())).unwrap();
    }

    #[test]
    fn rejects_non_canonical_compressed_field_element() {
        let err = unchecked_compressed_x_to_g1_point(&modulus_bytes_with_flag())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not Fq"));
    }

    #[test]
    fn rejects_compressed_g1_infinity() {
        let mut buffer = [0u8; 32];
        buffer[0] = COMPRESSED_INFINITY;
        let err = unchecked_compressed_x_to_g1_point(&buffer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("infinity"));
    }

    #[test]
    fn rejects_nonzero_compressed_g1_infinity_payload() {
        let mut buffer = [0u8; 32];
        buffer[0] = COMPRESSED_INFINITY | 1;
        let err = unchecked_compressed_x_to_g1_point(&buffer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid infinity encoding"));
    }

    #[test]
    fn rejects_compressed_g2_infinity() {
        let mut buffer = [0u8; 64];
        buffer[0] = COMPRESSED_INFINITY;
        let err = unchecked_compressed_x_to_g2_point(&buffer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("infinity"));
    }

    #[test]
    fn rejects_nonzero_compressed_g2_infinity_payload() {
        let mut buffer = [0u8; 64];
        buffer[0] = COMPRESSED_INFINITY;
        buffer[32] = 1;
        let err = unchecked_compressed_x_to_g2_point(&buffer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid infinity encoding"));
    }

    #[test]
    fn parses_valid_uncompressed_g1_and_g2_points() {
        uncompressed_bytes_to_g1_point(&uncompressed_g1(AffineG1::one())).unwrap();
        uncompressed_bytes_to_g2_point(&uncompressed_g2(AffineG2::one())).unwrap();
    }

    #[test]
    fn rejects_wrong_uncompressed_lengths() {
        assert!(uncompressed_bytes_to_g1_point(&[0u8; 63]).is_err());
        assert!(uncompressed_bytes_to_g2_point(&[0u8; 64]).is_err());
    }
}

mod verification_tests {
    use super::*;

    #[test]
    fn verify_reports_mismatched_input_length_before_pairing() {
        let vk = Groth16VKey::try_from(vk_bytes(6).as_slice()).unwrap();
        let proof = Groth16Proof::try_from(proof_bytes().as_slice()).unwrap();
        let inputs = [Fr::one(), Fr::one(), Fr::one()];

        let err = proof.verify(&vk, &inputs).unwrap_err().to_string();
        assert!(err.contains("input length mismatch"));
    }

    #[test]
    fn fake_but_well_formed_proof_fails_verification() {
        let vk = Groth16VKey::try_from(vk_bytes_with_gamma(1, AffineG2::one()).as_slice()).unwrap();
        let proof = Groth16Proof::try_from(proof_bytes().as_slice()).unwrap();
        let err = proof.verify(&vk, &[]).unwrap_err().to_string();
        assert!(err.contains("groth16 verification"));
    }

    #[test]
    fn matching_well_formed_proof_verifies() {
        let vk = Groth16VKey::try_from(vk_bytes(1).as_slice()).unwrap();
        let proof = Groth16Proof::try_from(proof_bytes().as_slice()).unwrap();
        proof.verify(&vk, &[]).unwrap();
    }
}

mod pairing_tests {
    use super::*;

    #[test]
    fn pairing_with_generator_points_completes() {
        let result = bn::pairing_batch(&[(G1::one(), G2::one())]);
        assert_ne!(result, Gt::one());
    }

    #[test]
    fn pairing_with_zero_point_is_identity() {
        let result = bn::pairing_batch(&[(G1::zero(), G2::one())]);
        assert_eq!(result, Gt::one());
    }
}
