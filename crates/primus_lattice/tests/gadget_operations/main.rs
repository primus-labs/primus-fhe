//! External-product and CMux contracts for coefficient, NTT and Fourier outputs.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, ggsw::Ggsw, ngsw::Ngsw, nlev::Nlev};
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_shape::PolyLength;

mod cmux_k;
mod external_product;
mod external_product_sum;
mod ternary_cmux;

const POLY_LENGTH: PolyLength = PolyLength::new(32);
const N: usize = POLY_LENGTH.get();

/// Builds a noiseless GGSW of one with one constant polynomial per diagonal level.
fn unit_ggsw<T: FheUint>(size: GadgetSize, basis: &ApproxSignedBasis<T>) -> Ggsw<Vec<T>> {
    let mut gadget = Ggsw::zero(size.ggsw_len());
    let glwe = size.glwe_size();
    let poly_length = glwe.poly_length().get();
    for (i, mut row) in gadget.iter_glev_mut(size.glev_len()).enumerate() {
        for (scalar, mut level) in basis.scalar_iter().zip(row.iter_glwe_mut(glwe.glwe_len())) {
            level.iter_poly_mut(poly_length).nth(i).unwrap().as_mut()[0] = scalar;
        }
    }
    gadget
}

/// With NTRU secret f=1, each noiseless unit control row is its gadget weight.
fn unit_ngsw<T: FheUint>(basis: &ApproxSignedBasis<T>) -> Ngsw<Vec<T>> {
    let mut control = Ngsw::zero(basis.level_count().get() * N);
    for (scalar, mut row) in basis.scalar_iter().zip(control.iter_ntru_mut(N)) {
        row.as_mut()[0] = scalar;
    }
    control
}

/// Encodes a noiseless polynomial under f=1 by multiplying it by each gadget weight.
fn noiseless_nlev<T: FheUint, M: RingContext<T>>(
    message: &Polynomial<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    modulus: M,
) -> Nlev<Vec<T>> {
    let mut gadget = Nlev::zero(basis.level_count().get() * N);
    for (scalar, mut level) in basis.scalar_iter().zip(gadget.iter_ntru_mut(N)) {
        message.mul_scalar_to(scalar, &mut Polynomial(level.as_mut()), modulus);
    }
    gadget
}

/// Share one plan per FFT engine. Each operation retains its own workspace and oracle.
fn check_fourier<Table: FftTable>(table: &Table) {
    external_product::check_fourier_ggsw(table);
    external_product::check_fourier_ntru(table);
    external_product_sum::check_fourier::<u32, _>(table);
    external_product_sum::check_fourier::<u64, _>(table);
    cmux_k::check_fourier(table);
    ternary_cmux::check_fourier::<u32, _>(table);
    ternary_cmux::check_fourier::<u64, _>(table);
}

#[test]
fn rustfft_gadget_operations() {
    check_fourier(&RustFftTable::new(POLY_LENGTH));
}

#[test]
fn tfhe_fft_gadget_operations() {
    check_fourier(&TfheFftTable::new(POLY_LENGTH));
}
