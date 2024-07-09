use std::marker::PhantomData;

use algebra::Field;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::utils::{
    arithmetic::ceil,
    code::{LinearCode, LinearCodeSpec},
    hash::Hash,
    merkle_tree::{MerkleRoot, MerkleTree},
};
use bincode::Result;

use crate::multilinear::brakedown::BRAKEDOWN_SECURITY_BIT;

/// Define the structure of Brakedown parameters.
#[derive(Serialize, Deserialize)]
pub struct BrakedownParams<F: Field, C: LinearCode<F>> {
    security_bit: usize,
    num_vars: usize,
    num_rows: usize,
    num_cols: usize,
    code: C,
    _marker: PhantomData<F>,
}

impl<F: Field, C: LinearCode<F>> BrakedownParams<F, C> {
    /// Create a new instance.
    ///
    /// # Arguments
    ///
    /// * `num_vars` - The number of variables supported.
    /// * `code_spec` - The specification of the code.
    /// * `rng` - Randomness generator.
    pub fn new(
        num_vars: usize,
        code_spec: impl LinearCodeSpec<F, Code = C>,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self {
        // Find the optimal num_cols to minimize proof size.

        // Estimated number of queries.
        let estimated_queries = |distance: f64, gap: f64| {
            ceil(-(BRAKEDOWN_SECURITY_BIT as f64) / (1.0 - distance * gap).log2())
        };

        // Estimated proof size.
        let estimated_proof_size = |codeword_len: usize, l: usize, msg_len: usize| {
            codeword_len + l * (1 << num_vars) / msg_len
        };

        let mut min_proof_size = usize::MAX;
        let mut num_cols = 0;
        let mut code = C::default();

        for log_msg_len in 4..num_vars {
            let msg_len = 1 << log_msg_len;
            let internal_code = code_spec.code(msg_len, rng);
            let proof_size = estimated_proof_size(
                internal_code.codeword_len(),
                estimated_queries(internal_code.distance(), internal_code.proximity_gap()),
                msg_len,
            );
            if proof_size < min_proof_size {
                num_cols = msg_len;
                min_proof_size = proof_size;
                code = internal_code;
            }
        }

        let num_rows = (1 << num_vars) / num_cols;

        Self {
            security_bit: BRAKEDOWN_SECURITY_BIT,
            num_vars,
            num_rows,
            num_cols,
            code,
            _marker: PhantomData,
        }
    }

    /// Return num_vars.
    #[inline]
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Return num_rows.
    #[inline]
    pub fn num_rows(&self) -> usize {
        self.num_rows
    }

    /// Return reference of code.
    pub fn code(&self) -> &C {
        &self.code
    }

    /// The soundness error specified by the security parameter for
    /// proximity test: (1-delta/3)^num_opening + (codeword_len/|F|)
    /// Return the number of columns needed to open,
    /// which accounts for the (1-delta/3)^num_opening part
    #[inline]
    pub fn num_query(&self) -> usize {
        let num_query = ceil(
            -(self.security_bit as f64)
                / (1.0 - self.code.distance() * self.code.proximity_gap()).log2(),
        );
        std::cmp::min(num_query, self.code.codeword_len())
    }
}

impl<F: Field, C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>> BrakedownParams<F, C> {
    /// Convert into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    /// Recover from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
    }
}

/// Polynoial Commitment of Brakedown
pub type BrakedownPolyCommitment<H> = MerkleRoot<H>;

/// Opening proof of Brakedown.
#[derive(Default, Serialize, Deserialize)]
pub struct BrakedownOpenProof<F, H: Hash> {
    /// Random linear combination of messages.
    pub rlc_msgs: Vec<F>,

    /// The opening columns according to the queres.
    pub opening_columns: Vec<F>,

    /// Merkle paths.
    pub merkle_paths: Vec<H::Output>,
}

impl<F: Field + Serialize + for<'de> Deserialize<'de>, H: Hash> BrakedownOpenProof<F, H> {
    /// Convert into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    /// Recover from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
    }
}

/// Commitment state of Brakedown
#[derive(Debug, Default)]
pub struct BrakedownCommitmentState<F: Field, H: Hash> {
    /// The matrix that represents the polynomial.
    pub matrix: Vec<F>,
    /// The Merkle tree generated from the matrix.
    pub merkle_tree: MerkleTree<H>,
}
