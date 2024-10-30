use std::marker::PhantomData;

use algebra::{utils::Prg, AbstractExtensionField, Field};
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
#[derive(Serialize, Deserialize, Default)]
pub struct BrakedownParams<F: Field, EF: AbstractExtensionField<F>, C: LinearCode<F>> {
    security_bit: usize,
    num_vars: usize,
    num_rows: usize,
    num_cols: usize,
    code: C,
    _marker: PhantomData<(F, EF)>,
}

impl<F: Field, EF: AbstractExtensionField<F>, C: LinearCode<F>> BrakedownParams<F, EF, C> {
    /// Create a new instance.
    ///
    /// # Arguments
    ///
    /// * `num_vars` - The number of variables supported.
    /// * `code_spec` - The specification of the code.
    /// * `rng` - Randomness generator.
    pub fn new(num_vars: usize, code_spec: impl LinearCodeSpec<F, Code = C>) -> Self {
        // Find the optimal num_cols to minimize proof size.

        // Estimated number of queries.
        let estimated_queries = |distance: f64, gap: f64| {
            ceil(-(BRAKEDOWN_SECURITY_BIT as f64) / (1.0 - distance * gap).log2())
        };
        let num_queries = estimated_queries(
            code_spec.distance().unwrap(),
            code_spec.proximity_gap().unwrap(),
        );

        // Estimated proof size.
        let estimated_proof_size =
            |msg_len: usize| msg_len * EF::D + num_queries * (1 << num_vars) / msg_len;

        // estimated proof size := num_cols + num_queries * num_rows = D * num_cols + (num_queries * (2 ^ num_vars)) / num_cols
        // since message is on extension field
        // optimal num_cols is the closest power of 2 to ((2 ^ num_vars) * num_queries / D) ^ (1/2)

        let sqrt = (((1 << num_vars) * num_queries / EF::D) as f64).sqrt();
        let lower = 1 << sqrt.log2().floor() as u32;
        let upper = 1 << sqrt.log2().ceil() as u32;

        let mut num_cols = if estimated_proof_size(lower) < estimated_proof_size(upper) {
            lower
        } else {
            upper
        };
        if num_cols > (1 << num_vars) {
            num_cols = 1 << num_vars;
        }

        let num_rows = (1 << num_vars) / num_cols;

        let code = code_spec.code(num_cols, &mut Prg::new());

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
    #[inline]
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

impl<
        F: Field,
        EF: AbstractExtensionField<F>,
        C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
    > BrakedownParams<F, EF, C>
{
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
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct BrakedownOpenProof<F, H, EF>
where
    F: Field,
    H: Hash,
    EF: AbstractExtensionField<F>,
{
    /// Random linear combination of messages.
    pub rlc_msgs: Vec<EF>,

    /// The opening columns according to the queres.
    pub opening_columns: Vec<F>,

    /// Merkle paths.
    pub merkle_paths: Vec<H::Output>,
}

impl<F, H, EF> BrakedownOpenProof<F, H, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    H: Hash,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Convert into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    /// Recover from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
    }
}

/// Opening proof of Brakedown for extension field.
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct BrakedownOpenProofGeneral<F, H>
where
    F: Field,
    H: Hash,
{
    /// Random linear combination of messages.
    pub rlc_msgs: Vec<F>,

    /// The opening columns according to the queres.
    pub opening_columns: Vec<F>,

    /// Merkle paths.
    pub merkle_paths: Vec<H::Output>,
}

impl<F, H> BrakedownOpenProofGeneral<F, H>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    H: Hash,
{
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
pub struct BrakedownCommitmentState<F: Field, H: Hash + Send + Sync> {
    /// The matrix that represents the polynomial.
    pub matrix: Vec<F>,
    /// The Merkle tree generated from the matrix.
    pub merkle_tree: MerkleTree<H>,
}
