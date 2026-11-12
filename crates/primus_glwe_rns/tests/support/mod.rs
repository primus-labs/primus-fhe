//! Codec-free fixtures. A power-of-two probe separates a known integer phase
//! from bounded evaluation error; it has no plaintext modulus or BFV decoder.
#![allow(dead_code)]

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweEncryptionParameters, DcrtGlweCiphertext, DcrtGlweSecretKey,
    SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use primus_shape::PolyLength;

pub const PROBE_SCALE: i128 = 1 << 42;

pub struct RawParameters<T: FheUint>
where
    BarrettModulus<T>: FieldContext<T>,
{
    pub core: CrtGlweEncryptionParameters<T>,
    pub base: RNSBase<T, BarrettModulus<T>>,
}

impl<T: FheUint> RawParameters<T>
where
    BarrettModulus<T>: FieldContext<T>,
{
    pub fn new(
        dimension: GlweDimension,
        n: PolyLength,
        moduli: &[BarrettModulus<T>],
        secret: SecretKeyDistr,
        sigma: f64,
    ) -> Self {
        let base = RNSBase::new(moduli).unwrap();
        let size = RnsGlweSize::new(GlweSize::new(dimension, n), base.moduli_count());
        let core = CrtGlweEncryptionParameters::try_new(size, &base, secret, sigma).unwrap();
        Self { core, base }
    }

    pub fn size(&self) -> RnsGlweSize {
        self.core.size()
    }
    pub fn glwe_size(&self) -> GlweSize {
        self.size().glwe_size()
    }
    pub fn poly_length(&self) -> PolyLength {
        self.size().poly_length()
    }
    pub fn rns_poly_len(&self) -> usize {
        self.size().rns_poly_len()
    }
    pub fn rns_glwe_len(&self) -> usize {
        self.size().rns_glwe_len()
    }
    pub fn encryption_parameters(&self) -> &CrtGlweEncryptionParameters<T> {
        &self.core
    }
    pub fn base_q(&self) -> &RNSBase<T, BarrettModulus<T>> {
        &self.base
    }
    pub fn secret_key_sampler(&self) -> &primus_distr::SecretKeySampler<T> {
        self.core.secret_key_sampler()
    }
    pub fn gadget(
        &self,
        log: DecompositionBaseLog,
        levels: Option<DecompositionLevelCount>,
    ) -> CrtGlevParameters<T, BarrettModulus<T>> {
        CrtGlevParameters::try_new(self.size(), self.base.clone(), log, levels).unwrap()
    }
}

/// Keep the polynomial short while exercising a product wider than one word.
pub fn probe_parameters(dimension: usize) -> RawParameters<u64> {
    let moduli = [1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new);
    RawParameters::new(
        GlweDimension::new(dimension),
        PolyLength::new(32),
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.2,
    )
}

pub fn encode_probe(message: &[i128], moduli: &[u64]) -> CrtPolynomial<Vec<u64>> {
    CrtPolynomial::new(
        moduli
            .iter()
            .flat_map(|&q| {
                message
                    .iter()
                    .map(move |&value| (PROBE_SCALE * value).rem_euclid(i128::from(q)) as u64)
            })
            .collect::<Vec<_>>(),
    )
}

pub fn unsigned_probe(message: &[u64], parameters: &RawParameters<u64>) -> CrtPolynomial<Vec<u64>> {
    encode_probe(
        &message
            .iter()
            .map(|&value| i128::from(value))
            .collect::<Vec<_>>(),
        parameters.base.moduli_values(),
    )
}

pub fn tree_error_bound(
    gadget: &CrtGlevParameters<u64, BarrettModulus<u64>>,
    sampling: &CrtGlweEncryptionParameters<u64>,
) -> i128 {
    let size = gadget.size().rns_glwe_size();
    let n = size.poly_length().get() as i128;
    // The complete normalized subtrees select signed coefficient positions;
    // their modular inverses do not leave fractional input error at a leaf.
    // Unnormalized sums can duplicate a switch error at most N times. The
    // geometric sum of their multiplicities is at most N-1.
    n * (i128::from(sampling.noise_distribution().maximum_magnitude())
        + switch_error_bound(gadget, sampling, size.dimension().get() as i128 * n))
}

pub fn assert_scalar_probe<Table: NttTable<ValueT = u64>>(
    key: &DcrtGlweSecretKey<u64>,
    parameters: &RawParameters<u64>,
    table: &DcrtTable<Table>,
    ciphertext: &DcrtGlweCiphertext<Vec<u64>>,
    expected: u64,
    error_bound: i128,
) {
    let mut message = vec![0; parameters.poly_length().get()];
    message[0] = i128::from(expected);
    assert_probe_phase(key, parameters, table, ciphertext, &message, error_bound);
}

pub fn phase<Table: NttTable<ValueT = u64>>(
    key: &DcrtGlweSecretKey<u64>,
    parameters: &RawParameters<u64>,
    table: &DcrtTable<Table>,
    ciphertext: &DcrtGlweCiphertext<Vec<u64>>,
) -> Vec<u64> {
    let mut output = DcrtPolynomial::new(vec![0; parameters.rns_poly_len()]);
    key.phase_to(ciphertext, &mut output, parameters.base.moduli());
    table.inverse_transform_slice(output.as_mut());
    output.into_inner()
}

pub fn assert_probe_phase<Table: NttTable<ValueT = u64>>(
    key: &DcrtGlweSecretKey<u64>,
    parameters: &RawParameters<u64>,
    table: &DcrtTable<Table>,
    ciphertext: &DcrtGlweCiphertext<Vec<u64>>,
    expected: &[i128],
    error_bound: i128,
) {
    let actual = phase(key, parameters, table, ciphertext);
    assert_eq!(expected.len(), parameters.poly_length().get());
    assert_phase_residues(
        &actual,
        parameters.base.moduli_values(),
        expected,
        error_bound,
    );
}

/// Checks a common bounded integer error, not independent per-prime errors.
/// Nearby powers of two and NTT primes can otherwise alias large probe values.
pub fn assert_phase_residues(actual: &[u64], moduli: &[u64], expected: &[i128], error_bound: i128) {
    let n = expected.len();
    assert!(!moduli.is_empty());
    assert_eq!(actual.len(), n * moduli.len());
    assert!(error_bound >= 0);
    assert!(
        2 * error_bound < PROBE_SCALE,
        "neighboring integer probes must have disjoint error intervals"
    );
    for &q in moduli {
        assert!(
            2 * error_bound < i128::from(q),
            "each limb must uniquely determine a bounded centered error"
        );
    }
    for (index, &expected) in expected.iter().enumerate() {
        let mut common_error = None;
        for (limb, &q) in moduli.iter().enumerate() {
            let q = i128::from(q);
            assert!(i128::from(actual[limb * n + index]) < q);
            let error =
                (i128::from(actual[limb * n + index]) - PROBE_SCALE * expected).rem_euclid(q);
            let error = if error > q / 2 { error - q } else { error };
            assert!(
                error.abs() <= error_bound,
                "limb={limb}, coefficient={index}, error={error}, bound={error_bound}"
            );
            if let Some(common_error) = common_error {
                assert_eq!(
                    error, common_error,
                    "coefficient={index}: all limbs must encode the same integer error"
                );
            } else {
                common_error = Some(error);
            }
        }
    }
}

/// One classical switch: each of k*N*L digits has magnitude at most B/2;
/// the decomposition residual is at most 2^(drop_bits-1) times the secret L1.
pub fn switch_error_bound(
    gadget: &CrtGlevParameters<u64, BarrettModulus<u64>>,
    sampling: &CrtGlweEncryptionParameters<u64>,
    secret_l1: i128,
) -> i128 {
    let size = gadget.size().rns_glwe_size();
    let e = i128::from(sampling.noise_distribution().maximum_magnitude());
    let digit = i128::from(gadget.basis().basis_value() / 2);
    let residual = if gadget.basis().drop_bits() == 0 {
        0
    } else {
        1i128 << (gadget.basis().drop_bits() - 1)
    };
    size.dimension().get() as i128
        * size.poly_length().get() as i128
        * gadget.level_count().get() as i128
        * digit
        * e
        + residual * secret_l1
}

pub fn convolution(left: &[i128], right: &[i128]) -> Vec<i128> {
    let n = left.len();
    let mut output = vec![0; n];
    for (i, &left) in left.iter().enumerate() {
        for (j, &right) in right.iter().enumerate() {
            output[(i + j) % n] += if i + j < n {
                left * right
            } else {
                -left * right
            };
        }
    }
    output
}
