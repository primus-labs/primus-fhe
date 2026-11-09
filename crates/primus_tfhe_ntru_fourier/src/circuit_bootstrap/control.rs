//! Shared consumption of ordinary CBS and one-hot NGSW controls.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_ntru::{FourierNgswCiphertext, NtruCiphertext};

use crate::{bootstrap::BootstrapResources, circuit_bootstrap::CbsGadgetParameters};

/// Consumes a bit control after the public evaluator has checked the resource
/// context. CBS binding established the basis and accumulator domain; raw
/// ciphertext views still require exact lengths before any output is written.
/// Slice views keep this implementation independent of caller-owned storage.
pub(super) fn cmux_to<T, Table>(
    parameters: &CbsGadgetParameters<T>,
    control: FourierNgswCiphertext<&[Complex64]>,
    lhs: NtruCiphertext<&[T]>,
    rhs: NtruCiphertext<&[T]>,
    mut output: NtruCiphertext<&mut [T]>,
    resources: &mut BootstrapResources<'_, T, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let ring_len = resources.context.poly_length().get();
    assert_eq!(
        (
            control.as_ref().len(),
            lhs.as_ref().len(),
            rhs.as_ref().len(),
            output.as_ref().len()
        ),
        (
            parameters.output_fourier_nlev_len(),
            ring_len,
            ring_len,
            ring_len
        ),
        "CMUX ciphertext layout mismatch"
    );
    control.cmux_to(
        &lhs,
        &rhs,
        &mut output,
        parameters.output_basis(),
        &mut resources.fft,
        resources.blind_rotation.rotation.external_product(),
    );
}

/// Uses the same CBS binding for a gadget product. The caller checked context
/// identity; lengths are checked here before writes, and the existing resource
/// owner supplies scratch. Unlike CMux, the control need not encrypt a bit.
pub(super) fn external_product_to<T, Table>(
    parameters: &CbsGadgetParameters<T>,
    control: FourierNgswCiphertext<&[Complex64]>,
    input: NtruCiphertext<&[T]>,
    mut output: NtruCiphertext<&mut [T]>,
    resources: &mut BootstrapResources<'_, T, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let ring_len = resources.context.poly_length().get();
    assert_eq!(
        (
            control.as_ref().len(),
            input.as_ref().len(),
            output.as_ref().len()
        ),
        (parameters.output_fourier_nlev_len(), ring_len, ring_len),
        "external-product ciphertext layout mismatch"
    );
    control.external_product_to(
        &input,
        &mut output,
        parameters.output_basis(),
        &mut resources.fft,
        resources.blind_rotation.rotation.external_product(),
    );
}
