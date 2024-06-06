use crate::utils::{
    arithmetic::{ceil, is_power_of_two},
    code::{BrakedownCode, BrakedownCodeSpec, LinearCode},
};
use algebra::{DenseMultilinearExtension, Field, FieldUniformSampler};
use rand::{distributions::Uniform, CryptoRng, Rng};
use sha3::{Digest, Sha3_256};
use std::{cmp::min, marker::PhantomData};

/// prover of brakedown pcs
pub mod prover;
/// verifier of brakedown pcs
pub mod verifier;

type ProverParam<F, C> = BrakedownParam<F, C>;
type VerifierParam<F, C> = BrakedownParam<F, C>;
type Polynomial<F> = DenseMultilinearExtension<F>;
/// 256bit hash value, whose length is determined by the security paranter
type Hash = [u8; 32];

/// Parameters of Brakedown Multilinear Polynomial Commitment Scheme
///
/// prover's pcs parameters and verifier's pcs parameters are the same for brakedown pcs
#[derive(Clone, Debug, Default)]
pub struct BrakedownParam<F: Field, C: LinearCode<F>> {
    /// security parameter
    pub lambda: usize,
    /// the number of the variables of the multilinear polynomial
    pub num_vars: usize,
    /// the number of the rows of the evaluation matrix of the multilinear polynomial
    pub num_rows: usize,
    /// the linear code in brakedown pcs
    pub code: C,
    /// phantomdata
    _marker: PhantomData<F>,
}

/// Protocol of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownProtocol<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> BrakedownProtocol<F> {
    /// transparent setup to reach a consensus of
    /// field of the polynomial,
    /// variable number of the polynomial,
    /// message length of the code (which enables variant overhead tradeoffs),
    /// code specification ( whic requires the same randomness for prover and verifier to generate the code)
    pub fn setup(
        lambda: usize,
        num_vars: usize,
        mut message_len: usize,
        code_spec: BrakedownCodeSpec,
        rng: impl Rng + CryptoRng,
    ) -> (
        ProverParam<F, BrakedownCode<F>>,
        VerifierParam<F, BrakedownCode<F>>,
    ) {
        // if message_len not specified, choose message_len that minimizes the proof size
        if message_len != 0 {
            assert!(is_power_of_two(message_len));
        } else {
            message_len = code_spec.optimize_message_len(num_vars);
        }

        // println!("num_query: {}", code_spec.num_queries());

        // input check
        assert!(1 << num_vars >= message_len);

        // create the pcs parameter
        let brakedown: BrakedownCode<F> = BrakedownCode::new(code_spec, message_len, rng);
        let param = BrakedownParam {
            lambda,
            num_vars,
            num_rows: (1 << num_vars) / brakedown.message_len(),
            code: brakedown,
            _marker: PhantomData,
        };
        let pp = param.clone();
        let vp = param;
        (pp, vp)
    }
}
