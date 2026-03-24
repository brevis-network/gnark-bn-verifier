use super::{
    io::{uncompressed_bytes_to_g1_point, uncompressed_bytes_to_g2_point},
    vk::Groth16VKey,
};
use anyhow::{anyhow, Result};
use bn::{pairing_batch, AffineG1, AffineG2, Fr, Gt, G1, G2};
use core::fmt::Debug;

pub struct Groth16Proof {
    #[allow(dead_code)]
    pub(crate) ar: AffineG1,
    #[allow(dead_code)]
    pub(crate) krs: AffineG1,
    #[allow(dead_code)]
    pub(crate) bs: AffineG2,
}

impl Debug for Groth16Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Groth16Proof").finish()
    }
}

fn prepare_inputs(vk: &Groth16VKey, public_inputs: &[Fr]) -> Result<G1> {
    if (public_inputs.len() + 1) != vk.g1.k.len() {
        return Err(anyhow!("input length mismatch"));
    }

    Ok(public_inputs
        .iter()
        .zip(vk.g1.k.iter().skip(1))
        .fold(vk.g1.k[0], |acc, (i, b)| acc + (*b * *i))
        .into())
}

impl Groth16Proof {
    pub fn verify(&self, vk: &Groth16VKey, public_inputs: &[Fr]) -> Result<()> {
        let prepared_inputs = prepare_inputs(vk, public_inputs)?;

        if pairing_batch(&[
            (-Into::<G1>::into(self.ar), self.bs.into()),
            (prepared_inputs, vk.g2.gamma.into()),
            (self.krs.into(), vk.g2.delta.into()),
            (vk.g1.alpha.into(), -Into::<G2>::into(vk.g2.beta)),
        ]) == Gt::one()
        {
            Ok(())
        } else {
            Err(anyhow!("groth16 verification"))
        }
    }
}

// attempt to deserialize some gnark formatted bytes into a proof
impl<'a> TryFrom<&'a [u8]> for Groth16Proof {
    type Error = anyhow::Error;

    fn try_from(buffer: &'a [u8]) -> anyhow::Result<Self> {
        if buffer.len() < 256 {
            return Err(anyhow!("invalid groth16 proof length: {}", buffer.len()));
        }

        let ar = uncompressed_bytes_to_g1_point(&buffer[..64])?;
        let bs = uncompressed_bytes_to_g2_point(&buffer[64..192])?;
        let krs = uncompressed_bytes_to_g1_point(&buffer[192..256])?;

        Ok(Groth16Proof { ar, bs, krs })
    }
}
