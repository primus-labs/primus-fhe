use crate::utils::{
    arithmetic::{ceil, lagrange_basis},
    code::{LinearCode, LinearCodeSpec},
    hash::Hash,
};
use algebra::{DenseMultilinearExtension, Field, FieldUniformSampler};
use rand::{distributions::Uniform, CryptoRng, Rng};
use std::{cmp::min, marker::PhantomData};

/// prover of brakedown pcs
pub mod prover;
/// verifier of brakedown pcs
pub mod verifier;

type ProverParam<F, C, H> = PcsParam<F, C, H>;
type VerifierParam<F, C, H> = PcsParam<F, C, H>;
type Polynomial<F> = DenseMultilinearExtension<F>;

/// Parameters of Brakedown Multilinear Polynomial Commitment Scheme
///
/// prover's pcs parameters and verifier's pcs parameters are the same for brakedown pcs
#[derive(Clone, Debug, Default)]
pub struct PcsParam<F: Field, C: LinearCode<F>, H: Hash> {
    /// security parameter
    pub security_bit: usize,
    /// the number of the variables of the multilinear polynomial
    pub num_vars: usize,
    /// the number of the rows of the evaluation matrix of the multilinear polynomial
    pub num_rows: usize,
    /// the linear code in brakedown pcs
    pub code: C,
    /// phantomdata
    _marker: PhantomData<(F, H)>,
}

/// Protocol of Brakedown PCS
#[derive(Debug, Clone, Default)]
pub struct BrakedownProtocol<F: Field, C: LinearCode<F>, H: Hash> {
    security_bit: usize,
    num_vars: usize,
    message_len: usize,
    code: C,
    _marker: PhantomData<(F, H)>,
}

impl<F: Field, C: LinearCode<F>, H: Hash> BrakedownProtocol<F, C, H> {
    /// instantiate a brakedown protocol with a consensus of
    /// field of the polynomial,
    /// variable number of the polynomial,
    /// message length of the code (which enables variant overhead tradeoffs),
    /// code specification ( whic requires the same randomness for prover and verifier to generate the code)
    pub fn new(
        security_bit: usize,
        num_vars: usize,
        message_len: usize,
        code_spec: impl LinearCodeSpec<F, Code = C>,
        rng: impl Rng + CryptoRng,
    ) -> Self {
        // input check
        assert!(message_len.is_power_of_two());
        assert!(1 << num_vars >= message_len);

        // create the code based on code_spec
        let code = code_spec.code(message_len, message_len, rng);
        //let code: ExpanderCode<F> = ExpanderCode::new(code_spec.clone(), message_len, rng);

        Self {
            security_bit,
            num_vars,
            message_len,
            code,
            ..Default::default()
        }
    }

    /// generate prover paramters and verifier parameters
    pub fn setup(&self) -> (ProverParam<F, C, H>, VerifierParam<F, C, H>) {
        let param = PcsParam {
            security_bit: self.security_bit,
            num_vars: self.num_vars,
            num_rows: (1 << self.num_vars) / self.message_len,
            code: self.code.clone(),
            _marker: PhantomData,
        };

        let pp = param.clone();
        let vp = param;
        (pp, vp)
    }

    /// compute relative proof size
    #[inline]
    pub fn estimated_proof_size(&self) -> usize {
        self.code.codeword_len() + self.num_query() * (1 << self.num_vars) / self.message_len
    }

    /// the soundness error specified by the security parameter for proximity test: (1-delta/3)^num_opening + (codeword_len/|F|)
    /// return the number of columns needed to open, which accounts for the (1-delta/3)^num_opening part
    #[inline]
    pub fn num_query(&self) -> usize {
        ceil(
            -(self.security_bit as f64)
                / (1.0 - self.code.distance() * self.code.proximity_gap()).log2(),
        )
    }
}
