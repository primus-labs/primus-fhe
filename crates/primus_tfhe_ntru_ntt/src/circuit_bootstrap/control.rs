//! Shared consumption of ordinary CBS and one-hot NGSW controls.

use primus_integer::FheUint;
use primus_ntru::{NtruCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;

use crate::{bootstrap::BootstrapResources, circuit_bootstrap::CbsGadgetParameters};

/// Consumes a bit control after the public evaluator has checked the resource
/// context. CBS binding established the basis and accumulator domain; raw
/// ciphertext views still require exact lengths before any output is written.
/// Slice views keep this implementation independent of caller-owned storage.
pub(super) fn cmux_to<T, Table>(
    parameters: &CbsGadgetParameters<T>,
    control: NttNgswCiphertext<&[T]>,
    lhs: NtruCiphertext<&[T]>,
    rhs: NtruCiphertext<&[T]>,
    mut output: NtruCiphertext<&mut [T]>,
    resources: &mut BootstrapResources<'_, T, Table>,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    let ring_len = resources.context.poly_length().get();
    assert_eq!(
        (
            control.as_ref().len(),
            lhs.as_ref().len(),
            rhs.as_ref().len(),
            output.as_ref().len()
        ),
        (parameters.output_nlev_len(), ring_len, ring_len, ring_len),
        "CMUX ciphertext layout mismatch"
    );
    control.cmux_to(
        &lhs,
        &rhs,
        &mut output,
        parameters.output_basis(),
        resources.context.accumulator_ntru().cipher_modulus(),
        resources.context.table(),
        resources.blind_rotation.rotation.external_product(),
    );
}

/// Uses the same CBS binding for a gadget product. The caller checked context
/// identity; lengths are checked here before writes, and the existing resource
/// owner supplies scratch. Unlike CMux, the control need not encrypt a bit.
pub(super) fn external_product_to<T, Table>(
    parameters: &CbsGadgetParameters<T>,
    control: NttNgswCiphertext<&[T]>,
    input: NtruCiphertext<&[T]>,
    mut output: NtruCiphertext<&mut [T]>,
    resources: &mut BootstrapResources<'_, T, Table>,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    let ring_len = resources.context.poly_length().get();
    assert_eq!(
        (
            control.as_ref().len(),
            input.as_ref().len(),
            output.as_ref().len()
        ),
        (parameters.output_nlev_len(), ring_len, ring_len),
        "external-product ciphertext layout mismatch"
    );
    control.external_product_to(
        &input,
        &mut output,
        parameters.output_basis(),
        resources.context.accumulator_ntru().cipher_modulus(),
        resources.context.table(),
        resources.blind_rotation.rotation.external_product(),
    );
}
