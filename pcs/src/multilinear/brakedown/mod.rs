use crate::utils::code::{BrakedownCode, BrakedownCodeSpec, LinearCode};
use algebra::{DenseMultilinearExtension, Field, FieldUniformSampler};
use rand::{distributions::Uniform, Rng, RngCore};
use sha3::{Digest, Sha3_256};
use std::marker::PhantomData;

/// prover of brakedown pcs
pub mod prover;
/// verifier of brakedown pcs
pub mod verifier;

type ProverParam<F> = BrakedownParam<F>;
type VerifierParam<F> = BrakedownParam<F>;
type Polynomial<F> = DenseMultilinearExtension<F>;
/// 256bit hash value, whose length is determined by the security paranter
type Hash = [u8; 32];

/// Parameters of Brakedown Multilinear Polynomial Commitment Scheme
///
/// prover's pcs parameters and verifier's pcs parameters are the same for brakedown pcs
#[derive(Clone, Debug, Default)]
pub struct BrakedownParam<F: Field> {
    /// the number of the variables of the multilinear polynomial
    pub num_vars: usize,
    /// the number of the rows of the evaluation matrix of the multilinear polynomial
    pub num_rows: usize,
    /// the linear code in brakedown pcs
    pub brakedown: BrakedownCode<F>,
}

/// Protocol of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownProtocol<F: Field> {
    field: PhantomData<F>,
}

impl<F: Field> BrakedownProtocol<F> {
    /// transparent setup to reach a consensus of
    /// field of the polynomial,
    /// variable number of the polynomial,
    /// message length of the code (which enables variant overhead tradeoffs),
    /// code specification ( whic requires the same randomness for prover and verifier to generate the code)
    pub fn setup(
        num_vars: usize,
        message_lenn: usize,
        spec: BrakedownCodeSpec,
        rng: impl RngCore,
    ) -> (ProverParam<F>, VerifierParam<F>) {
        // if message_len not specified, choose message_len that minimizes the proof size
        // let mut row_len = 0;
        // let _ = 0;
        // if message_len != 0 {
        //     assert!(is_power_of_two(message_len));
        // } else {
        //     let log_threshold = (spec.recursion_threshold() + 1).next_power_of_two().ilog2() as usize;
        //     (_, row_len) =
        //     (log_threshold..=num_vars).fold((usize::MAX, 0), |(min_proof_size, row_len), log_row_len| {
        //         let proof_size = spec.proof_size(1 << log_row_len, 1 << (num_vars - log_row_len));
        //         if proof_size < min_proof_size {
        //             (proof_size, 1 << log_row_len)
        //         } else {
        //             (min_proof_size, row_len)
        //         }
        //     });
        // }
        println!("num_query: {}", spec.num_queries());
        let mut message_len: usize = 0;
        if message_lenn == 0 {
            message_len = 1 << (num_vars / 2 + 1);
        }

        // input check
        assert!(1 << num_vars >= message_len);

        // create the pcs parameter
        let brakedown: BrakedownCode<F> = BrakedownCode::new(spec, message_len, rng);
        let param = BrakedownParam {
            num_vars,
            num_rows: (1 << num_vars) / brakedown.message_len(),
            brakedown,
        };
        let pp = param.clone();
        let vp = param;
        (pp, vp)
    }
}

// #[inline]
// fn is_power_of_two(x: usize) -> bool {
//     x != 0 && (x & (x - 1)) == 0
// }
