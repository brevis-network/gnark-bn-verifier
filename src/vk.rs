use anyhow::anyhow;
use super::{
    io::{unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point},
    types::{Groth16G1, Groth16G2},
};

#[derive(Clone, PartialEq, Debug)]
pub struct Groth16VKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

impl Groth16VKey {
    /// Returns the number of public inputs expected (k.len() - 1)
    pub fn num_public_inputs(&self) -> usize {
        self.g1.k.len().saturating_sub(1)
    }
}

// attempt to deserialize some gnark formatted bytes into a vkey
impl<'a> TryFrom<&'a [u8]> for Groth16VKey {
    type Error = anyhow::Error;

    fn try_from(buffer: &'a [u8]) -> anyhow::Result<Self> {
        // Minimum length: 292 bytes (header) + at least 32 bytes for one K point
        if buffer.len() < 292 {
            return Err(anyhow!("vkey buffer too short: {}", buffer.len()));
        }

        let g1_alpha = unchecked_compressed_x_to_g1_point(&buffer[..32])?;
        let g2_beta = unchecked_compressed_x_to_g2_point(&buffer[64..128])?;
        let g2_gamma = unchecked_compressed_x_to_g2_point(&buffer[128..192])?;
        let g2_delta = unchecked_compressed_x_to_g2_point(&buffer[224..288])?;

        let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);

        // Reasonable upper bound to prevent OOM: 10^6 points ≈ 32MB
        const MAX_K_COUNT: u32 = 1_000_000;
        if num_k > MAX_K_COUNT {
            return Err(anyhow!("vkey num_k too large: {}", num_k));
        }

        let expected_len = 292 + (num_k as usize) * 32;
        if buffer.len() < expected_len {
            return Err(anyhow!(
                "vkey buffer too short for {} k points: {}",
                num_k,
                buffer.len()
            ));
        }

        let mut k = Vec::with_capacity(num_k as usize);
        let mut offset = 292;
        for _ in 0..num_k {
            let point = unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
            k.push(point);
            offset += 32;
        }

        Ok(Self {
            g1: Groth16G1 { alpha: g1_alpha, k },
            g2: Groth16G2 {
                beta: -g2_beta,
                gamma: g2_gamma,
                delta: g2_delta,
            },
        })
    }
}
