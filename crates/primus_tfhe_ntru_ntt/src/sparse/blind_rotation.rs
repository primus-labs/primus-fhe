//! Bucket aggregation and reusable sparse blind-rotation workspace.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    nlev::{Nlev, NlevIter},
    ntru::Ntru,
};
use primus_lwe::LweDimension;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NttNtruExternalProductWorkspace};
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_reduce::ReduceOnceSlice;
use primus_tfhe_ntru::NtruBlindRotationControls;

use super::SparseNtruBootstrappingKey;

/// Reusable aggregate and product scratch, independent of bucket geometry.
pub(crate) struct AggregationWorkspace<T: FheUint> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    pub(crate) external_product: NttNtruExternalProductWorkspace<T>,
}

impl<T: FheUint> AggregationWorkspace<T> {
    pub(crate) fn new(
        parameters: &NlevParameters<T, BarrettModulus<T>>,
        controls: &NtruBlindRotationControls<T>,
    ) -> Self {
        Self {
            exponents: vec![0; controls.input_dimension().get()],
            aggregate: vec![T::ZERO; controls.control_len()],
            external_product: NttNtruExternalProductWorkspace::new(parameters.poly_length()),
        }
    }
}

/// Additional state for a second sparse blind-rotation input.
/// Allocate through [`crate::circuit_bootstrap::OneHotCircuitBootstrapEvaluator::new_sparse_pair_workspace`].
/// Retains only exponents, an L*N coefficient aggregate and one N-coefficient
/// accumulator; the original resources provide shared transform/product scratch.
pub struct SparseBlindRotationPairWorkspace<T: FheUint> {
    pub(crate) exponents: Vec<usize>,
    pub(crate) aggregate: Vec<T>,
    pub(crate) current: Ntru<Vec<T>>,
}

impl<T: FheUint> SparseBlindRotationPairWorkspace<T> {
    pub(crate) fn new(
        parameters: &NlevParameters<T, BarrettModulus<T>>,
        input_dimension: LweDimension,
    ) -> Self {
        Self {
            exponents: vec![0; input_dimension.get()],
            aggregate: vec![T::ZERO; parameters.nlev_len()],
            current: Ntru::zero(parameters.poly_length().get()),
        }
    }
}

/// The evaluator established key/workspace/table compatibility and quantized every mask.
/// Every bucket is processed, including empty ones and zero exponents; its encrypted
/// dummy and zero selections still contribute noise. `scratch` initially holds the
/// public rotated LUT. Bucket zero lifts it with NLEV controls; later buckets use
/// NGSW controls. Final output stays in `current`, even with just one bucket.
pub(crate) fn rotate_buckets<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) {
    let n = ntt.poly_length().get();
    // Start with public P in current. Bucket 0 uses NLEV[H_0] to lift P;
    // buckets >= 1 actually hold NGSW[H_j] = NLEV[f*H_j] and act on ciphertexts.
    // NLEV and NGSW external products have identical arithmetic, so all buckets
    // share this NLEV product call without a first-bucket branch.
    core::mem::swap(current, scratch);
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        aggregate_bucket(
            indices,
            data,
            [(
                &workspace.exponents,
                Nlev::new(workspace.aggregate.as_mut_slice()),
            )],
            n,
            modulus,
        );
        let aggregate = Nlev::new(workspace.aggregate.as_mut_slice()).into_ntt_form(ntt);
        aggregate.external_product_to(
            &Polynomial(current.as_ref()),
            scratch,
            basis,
            modulus,
            ntt,
            &mut workspace.external_product,
        );
        core::mem::swap(current, scratch);
    }
}

/// Both current buffers hold their independently rotated public LUT on entry.
/// Each source-control group is consumed for both inputs before advancing;
/// transforms and external products then reuse the original shared scratch.
pub(crate) fn rotate_buckets_pair<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    second: &mut SparseBlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) {
    let [current, scratch] = buffers;
    let n = ntt.poly_length().get();
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        aggregate_bucket(
            indices,
            data,
            [
                (
                    &workspace.exponents,
                    Nlev::new(workspace.aggregate.as_mut_slice()),
                ),
                (
                    &second.exponents,
                    Nlev::new(second.aggregate.as_mut_slice()),
                ),
            ],
            n,
            modulus,
        );
        // Bucket zero lifts both public LUTs with NLEV. Later NGSW controls
        // use the same external-product arithmetic, preserving every bucket.
        for (aggregate, current) in [
            (&mut workspace.aggregate, &mut *current),
            (&mut second.aggregate, &mut second.current),
        ] {
            let aggregate = Nlev::new(aggregate.as_mut_slice()).into_ntt_form(ntt);
            aggregate.external_product_to(
                &Polynomial(current.as_ref()),
                scratch,
                basis,
                modulus,
                ntt,
                &mut workspace.external_product,
            );
            core::mem::swap(current, scratch);
        }
    }
}

/// Starts from the encrypted dummy and adds every selector in key order. Pairing
/// shares an accumulator traversal without skipping zero exponents or encrypted
/// zeros; an odd final selector uses the single-product kernel. For u64, pairs
/// retain [0,2q) residues until one final normalization before NTT; other widths
/// retain canonical updates. The key and workspace establish complete, equally
/// sized controls and canonical source residues.
/// Instantiated only for one input or the fixed two-input window.
#[inline]
fn aggregate_bucket<T: FheUint, const INPUTS: usize>(
    indices: &[usize],
    data: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
    modulus: BarrettModulus<T>,
) {
    let control_len = inputs[0].1.as_ref().len();
    let (selections, dummy) = data.split_at(data.len() - control_len);
    for (_, aggregate) in &mut inputs {
        aggregate.as_mut().copy_from_slice(dummy);
    }
    let mut controls = indices.iter().zip(NlevIter::new(selections, control_len));
    while let Some((&first_index, first)) = controls.next() {
        if let Some((&second_index, second)) = controls.next() {
            for (exponents, aggregate) in &mut inputs {
                let exponent = exponents[first_index];
                if T::BITS == 64 {
                    primus_poly::lazy_add_mul_monomial_pair_assign(
                        aggregate.as_mut(),
                        first.as_ref(),
                        exponent,
                        second.as_ref(),
                        exponents[second_index],
                        poly_length,
                        modulus,
                    );
                } else {
                    aggregate.add_mul_monomial_pair_assign(
                        &first,
                        exponent,
                        &second,
                        exponents[second_index],
                        poly_length,
                        modulus,
                    );
                }
            }
        } else {
            for (exponents, aggregate) in &mut inputs {
                let exponent = exponents[first_index];
                if T::BITS == 64 {
                    primus_poly::lazy_add_mul_monomial_assign(
                        aggregate.as_mut(),
                        first.as_ref(),
                        exponent,
                        poly_length,
                        modulus,
                    );
                } else {
                    aggregate.add_mul_monomial_assign(&first, exponent, poly_length, modulus);
                }
            }
        }
    }
    if T::BITS == 64 {
        for (_, aggregate) in &mut inputs {
            modulus.reduce_once_slice_assign(aggregate.as_mut());
        }
    }
}
