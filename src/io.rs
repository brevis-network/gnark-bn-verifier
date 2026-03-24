use anyhow::{anyhow, Result};
use bn::{AffineG1, AffineG2, Fq, Fq2};
use core::cmp::Ordering;

const MASK: u8 = 0b11 << 6;
const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(Debug, PartialEq, Eq)]
enum CompressedPointFlag {
    Positive = COMPRESSED_POSITIVE as isize,
    Negative = COMPRESSED_NEGATIVE as isize,
    Infinity = COMPRESSED_INFINITY as isize,
}

impl TryFrom<u8> for CompressedPointFlag {
    type Error = anyhow::Error;

    fn try_from(val: u8) -> anyhow::Result<Self> {
        match val {
            COMPRESSED_POSITIVE => Ok(CompressedPointFlag::Positive),
            COMPRESSED_NEGATIVE => Ok(CompressedPointFlag::Negative),
            COMPRESSED_INFINITY => Ok(CompressedPointFlag::Infinity),
            _ => Err(anyhow!("invalid compressed point flag: {}", val)),
        }
    }
}

impl From<CompressedPointFlag> for u8 {
    fn from(value: CompressedPointFlag) -> Self {
        value as u8
    }
}

fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, CompressedPointFlag)> {
    if buf.len() != 32 {
        return Err(anyhow!("wrong size buffer"));
    };

    let m_data = buf[0] & MASK;
    if m_data == u8::from(CompressedPointFlag::Infinity) {
        // Checks if the first byte is zero after masking AND the rest of the bytes are zero.
        if buf[0] & !MASK == 0 && buf[1..].iter().all(|&b| b == 0) {
            return Err(anyhow!("invalid point"));
        }
        Ok((Fq::zero(), CompressedPointFlag::Infinity))
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes).expect("Failed to convert x bytes to Fq");

        Ok((x, CompressedPointFlag::try_from(m_data)?))
    }
}

pub fn unchecked_compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    let (x, m_data) = deserialize_with_flags(buf)?;
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x).ok_or(anyhow!("invalid point"))?;

    let mut final_y = y;
    if y.cmp(&neg_y) == Ordering::Greater {
        if m_data == CompressedPointFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressedPointFlag::Negative {
        final_y = -y;
    }

    Ok(AffineG1::new_unchecked(x, final_y))
}

pub fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    if buf.len() != 64 {
        return Err(anyhow!("invalid g1 length"));
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(x_bytes).map_err(|x| anyhow!("not Fq: {}", x))?;
    let y = Fq::from_slice(y_bytes).map_err(|x| anyhow!("not Fq: {}", x))?;
    AffineG1::new(x, y).map_err(|x| anyhow!("not on curve: {}", x))
}

pub fn unchecked_compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2> {
    if buf.len() != 64 {
        return Err(anyhow!("invalid g2 x length"));
    };

    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]).map_err(|x| anyhow!("not Fq: {}", x))?;
    let x = Fq2::new(x0, x1);

    if flag == CompressedPointFlag::Infinity {
        return Ok(AffineG2::one());
    }

    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x).ok_or(anyhow!("invalid point"))?;

    match flag {
        CompressedPointFlag::Positive => Ok(AffineG2::new_unchecked(x, y)),
        CompressedPointFlag::Negative => Ok(AffineG2::new_unchecked(x, neg_y)),
        _ => Err(anyhow!("invalid point")),
    }
}

pub fn uncompressed_bytes_to_g2_point(buf: &[u8]) -> Result<AffineG2> {
    if buf.len() != 128 {
        return Err(anyhow!("invalid g2 length"));
    }

    let (x_bytes, y_bytes) = buf.split_at(64);
    let (x1_bytes, x0_bytes) = x_bytes.split_at(32);
    let (y1_bytes, y0_bytes) = y_bytes.split_at(32);

    let x1 = Fq::from_slice(x1_bytes).map_err(|x| anyhow!("not Fq: {}", x))?;
    let x0 = Fq::from_slice(x0_bytes).map_err(|x| anyhow!("not Fq: {}", x))?;
    let y1 = Fq::from_slice(y1_bytes).map_err(|x| anyhow!("not Fq: {}", x))?;
    let y0 = Fq::from_slice(y0_bytes).map_err(|x| anyhow!("not Fq: {}", x))?;

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    AffineG2::new(x, y).map_err(|x| anyhow!("not on curve: {}", x))
}
