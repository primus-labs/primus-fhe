//! Coefficient aggregation and blind rotation for grouped NTRU controls.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    nlev::{Nlev, NlevIter},
    ntru::Ntru,
};
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NttNtruExternalProductWorkspace};
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_reduce::ReduceOnceSlice;
use primus_tfhe_ntru::NtruBlindRotationControls;

use crate::bootstrap::BlindRotationPairWorkspace;

/// Reusable aggregate and product scratch, independent of group geometry.
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

/// The first group's NLEV aggregate lifts public P; later groups actually hold
/// `NGSW[H] = NLEV[f*H]` and act on ciphertexts. Their product arithmetic agrees,
/// so the same loop consumes every block, including encrypted zeros and any
/// dummy. On entry, `scratch` holds the public rotated LUT. The final
/// coefficient-domain result stays in `current`.
pub(crate) fn rotate_groups<'a, T, Table, I>(
    groups: impl Iterator<Item = (I, &'a [T])>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    I: ExactSizeIterator<Item = usize>,
{
    let n = ntt.poly_length().get();
    core::mem::swap(current, scratch);
    for (indices, data) in groups {
        aggregate_controls(
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

/// Aggregates each group's controls for both inputs before advancing, preserving
/// each input's control order. Both current buffers initially hold independent
/// public LUT rotations: the complete first group, including any dummy, lifts
/// each through NLEV; later NGSW groups use the same external-product arithmetic.
/// Transform/product scratch is shared serially, with final results in the two
/// current buffers. The caller established all key, exponent and buffer geometry.
pub(crate) fn rotate_groups_pair<'a, T, Table, I>(
    groups: impl Iterator<Item = (I, &'a [T])>,
    workspace: &mut AggregationWorkspace<T>,
    second: &mut BlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    I: ExactSizeIterator<Item = usize>,
{
    let [current, scratch] = buffers;
    let n = ntt.poly_length().get();
    for (indices, data) in groups {
        aggregate_controls(
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

/// Starts from the encrypted dummy when present, otherwise clears the aggregate,
/// then adds every selector in key order. The iterator selects coordinates
/// from each input's exponent slice. Pairing shares an accumulator traversal
/// and includes zero exponents and encrypted zeros. An odd final selector uses
/// the single-product kernel. For u64, pairs retain [0,2q) residues until one
/// final normalization before NTT. Other widths retain canonical updates.
/// The key and workspace establish complete, equally sized controls and
/// canonical source residues.
/// Instantiated only for one input or the fixed two-input window.
#[inline]
fn aggregate_controls<T: FheUint, const INPUTS: usize>(
    indices: impl ExactSizeIterator<Item = usize>,
    data: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
    modulus: BarrettModulus<T>,
) {
    let control_len = inputs[0].1.as_ref().len();
    // The owner supplies w bit controls and either one complete dummy or none.
    // An empty slice denotes absence; it is never treated as a ciphertext.
    let (selections, dummy) = data.split_at(indices.len() * control_len);
    debug_assert!(dummy.is_empty() || dummy.len() == control_len);
    for (_, aggregate) in &mut inputs {
        if dummy.is_empty() {
            aggregate.as_mut().fill(T::ZERO);
        } else {
            aggregate.as_mut().copy_from_slice(dummy);
        }
    }
    let mut controls = indices.zip(NlevIter::new(selections, control_len));
    while let Some((first_index, first)) = controls.next() {
        if let Some((second_index, second)) = controls.next() {
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
