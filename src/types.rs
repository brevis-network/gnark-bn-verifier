use alloc::vec::Vec;
use bn::{AffineG1, AffineG2};

#[derive(Clone, PartialEq, Debug)]
pub struct Groth16G1 {
    pub(crate) alpha: AffineG1,
    pub(crate) k: Vec<AffineG1>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Groth16G2 {
    pub(crate) beta: AffineG2,
    pub(crate) delta: AffineG2,
    pub(crate) gamma: AffineG2,
}
