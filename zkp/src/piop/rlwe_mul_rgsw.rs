//! PIOP for multiplication between RLWE ciphertext and RGSW ciphertext

use std::marker::PhantomData;
use std::rc::Rc;
use crate::sumcheck::prover::ProverState;
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::{prover::ProverMsg, Proof};
use crate::sumcheck::{self, MLSumcheck};
use crate::utils::{eval_identity_function, gen_identity_evaluations};

use algebra::{
    DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension, PolynomialInfo,
    FieldUniformSampler,
};
use rand_distr::Distribution;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

pub struct RlweMultRgswIOP<Field>(PhantomData<F>);


pub struct RlweMultRgswInstance<F: Field> {
    pub log_n: usize,
    pub ntt_table: Vec<F>,
    pub rlwe_a_coeffs: Rc<DenseMultilinearExtension<F>>,
    pub rlwe_b_coeffs: Rc<DenseMultilinearExtension<F>>,
    pub rlwe_a_bits_coeffs: Vec<Rc<DenseMultilinearExtension<F>>>,
    pub rlwe_b_bits_coeffs: Vec<Rc<DenseMultilinearExtension<F>>>,
    pub rlwe_a_bits_points: Vec<Rc<DenseMultilinearExtension<F>>>,
    pub rlwe_b_bits_points: Vec<Rc<DenseMultilinearExtension<F>>>,
    pub rgsw_c_bits_points: Vec<Rc<DenseMultilinearExtension<F>>>,
    pub rgsw_f_bits_points: Vec<Rc<DenseMultilinearExtension<F>>>,
    pub rgsw_c_points: Rc<DenseMultilinearExtension<F>>,
    pub rgsw_f_points: Rc<DenseMultilinearExtension<F>>,
    pub rgsw_c_coeffs: Rc<DenseMultilinearExtension<F>>,
    pub rgsw_f_coeffs: Rc<DenseMultilinearExtension<F>>,

}