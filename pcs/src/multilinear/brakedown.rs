// use crate::{
//     multilinear::PolynomialCommitmentScheme,
//     utils::{
//         arithmetic::div_ceil,
//         code::{BrakedownCode, BrakedownCodeSpec},
//     },
// };

// use algebra::{derive::*, DenseMultilinearExtension, Field, MultilinearExtension};

// use std::{fmt::Debug, marker::PhantomData};

// use rand::RngCore;
// //use rayon;

// use sha3::{Digest, Sha3_256};

// pub use sha3::{
//     digest::{FixedOutputReset, Output, Update},
//     Keccak256,
// };

// pub struct MultilinearBrakedownParam<F: Field> {
//     num_vars: usize,
//     num_rows: usize,
//     brakedown: BrakedownCode<F>,
// }

// impl<F: Field> MultilinearBrakedownParam<F> {
//     pub fn num_vars(&self) -> usize {
//         self.num_vars
//     }

//     pub fn num_rows(&self) -> usize {
//         self.num_rows
//     }

//     pub fn brakedown(&self) -> &BrakedownCode<F> {
//         &self.brakedown
//     }
// }

// pub struct MultilinearBrakedownCommitment<F, H> {
//     rows: Vec<F>,
//     intermediate_hashes: Vec<H>,
//     root: H,
// }

// impl<F: Field, H> MultilinearBrakedownCommitment<F, H> {
//     pub fn commit(poly: DenseMultilinearExtension<F>) {}
// }
