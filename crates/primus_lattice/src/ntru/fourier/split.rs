//! Split gadget rows and two-limb external products.
use crate::workspace::{FourierNtruExternalProductWorkspace, FourierNtruSplitWorkspace};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_poly::{
    FourierPolynomial, FourierPolynomialIter, FourierPolynomialIterMut, PolynomialIter,
};
use primus_shape::PolyLength;

/// Two torus-scaled spectra per native gadget row: K = low + 2^b high.
/// This is evaluation material, not an ordinary Fourier NLEV/NGSW ciphertext.
/// A view of either limb alone has no ordinary encrypted-message interpretation.
#[derive(Clone)]
pub struct FourierNtruSplitGadget<T: TorusFftValue> {
    low: Vec<Complex64>,
    high: Vec<Complex64>,
    basis: ApproxSignedBasis<T>,
    low_bits: u32,
    n: PolyLength,
}
impl<T: TorusFftValue> FourierNtruSplitGadget<T> {
    /// Transforms exact native coefficient rows in decomposition order.
    /// Both limbs use the same FFT table and normalized torus scale.
    ///
    /// # Panics
    /// Requires native u64, b in 1..64, and exactly N*L coefficients.
    ///
    /// # Correctness
    /// This validates representation, not floating-point precision. Budget both
    /// low-limb error and high-limb rounding failures (amplified by 2^b).
    #[must_use]
    pub fn from_coefficients<Table: FftTable>(
        coefficients: &[T],
        basis: &ApproxSignedBasis<T>,
        low_bits: u32,
        fft: &mut FftEngine<'_, Table>,
    ) -> Self {
        assert!(
            T::BITS == 64 && basis.modulus().is_none() && (1..64).contains(&low_bits),
            "split NTRU requires native u64 and 0 < low_bits < 64"
        );
        let n = fft.poly_length();
        assert_eq!(
            coefficients.len(),
            n.get() * basis.level_count().get(),
            "split gadget coefficient length mismatch"
        );
        let mut result = Self {
            low: vec![Complex64::default(); coefficients.len() / 2],
            high: vec![Complex64::default(); coefficients.len() / 2],
            basis: basis.clone(),
            low_bits,
            n,
        };
        let mut limb = vec![T::ZERO; n.get()];
        let mask = (T::ONE << low_bits) - T::ONE;
        for ((row, mut low), mut high) in PolynomialIter::new(coefficients, n.get())
            .zip(FourierPolynomialIterMut::new(
                &mut result.low,
                n.fourier_poly_len(),
            ))
            .zip(FourierPolynomialIterMut::new(
                &mut result.high,
                n.fourier_poly_len(),
            ))
        {
            for (v, &x) in limb.iter_mut().zip(row.as_ref()) {
                *v = x & mask;
            }
            fft.forward_as_torus(&limb, low.as_mut());
            for (v, &x) in limb.iter_mut().zip(row.as_ref()) {
                *v = x >> low_bits;
            }
            fft.forward_as_torus(&limb, high.as_mut());
        }
        result
    }
    /// Returns the limb split bound to this material.
    #[must_use]
    pub fn low_bits(&self) -> u32 {
        self.low_bits
    }
    /// Returns the row decomposition used by this material.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }
    /// Returns the coefficient ring length.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.n
    }
    /// Allocates a matching combined-control buffer; no ciphertext data is copied.
    #[must_use]
    pub fn zero_like(&self) -> Self {
        Self {
            low: vec![Complex64::default(); self.low.len()],
            high: vec![Complex64::default(); self.high.len()],
            basis: self.basis.clone(),
            low_bits: self.low_bits,
            n: self.n,
        }
    }
    /// Forms initializer + (X^a-1)*first independently in both limbs.
    /// This represents a signed sum of limbs, not a canonical re-splitting.
    ///
    /// # Correctness
    /// Keys must use the same secret and FFT instance. Budget the extra factor
    /// and addition in the first lifted product. a=0 still performs public lifting.
    /// # Panics
    /// Checks compatible material and resources before writes.
    pub fn combine_lift<Table: FftTable>(
        &mut self,
        initializer: &Self,
        first: &Self,
        exponent: usize,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) {
        assert!(
            self.compatible(initializer) && self.compatible(first),
            "split lift material mismatch"
        );
        assert_eq!(fft.poly_length(), self.n, "split lift FFT mismatch");
        assert_eq!(
            workspace.poly_length(),
            self.n,
            "split lift workspace mismatch"
        );
        let w = workspace.as_mut();
        w.decomposed_poly.fill(T::ZERO);
        let a = exponent & (2 * self.n.get() - 1);
        w.decomposed_poly[a & (self.n.get() - 1)] = if a < self.n.get() {
            T::ONE
        } else {
            T::ZERO.wrapping_sub(T::ONE)
        };
        fft.forward_as_integer(w.decomposed_poly, w.decomposed_fourier);
        for f in w.decomposed_fourier.iter_mut() {
            f.re -= 1.0;
        }
        for (destination, initializer, first) in [
            (&mut self.low, &initializer.low, &first.low),
            (&mut self.high, &initializer.high, &first.high),
        ] {
            let length = self.n.fourier_poly_len();
            for ((mut out, init), control) in FourierPolynomialIterMut::new(destination, length)
                .zip(FourierPolynomialIter::new(initializer, length))
                .zip(FourierPolynomialIter::new(first, length))
            {
                out.as_mut().copy_from_slice(init.as_ref());
                out.add_mul_assign(&FourierPolynomial(&*w.decomposed_fourier), &control);
            }
        }
    }
    fn compatible(&self, rhs: &Self) -> bool {
        self.n == rhs.n && self.low_bits == rhs.low_bits && self.basis == rhs.basis
    }
    /// Overwrites one coefficient product without allocation.
    /// Each digit FFT feeds two accumulators. Inverse-round each limb separately,
    /// then wrapping-recombine; combining spectra before rounding loses precision.
    ///
    /// # Correctness
    /// Input is canonical native u64; FFT must be the key's generating table.
    /// Exact limb convolution magnitude must fit the inverse conversion's i128
    /// range. This is not an FFT accuracy bound: high error 1 becomes 2^b.
    /// # Panics
    /// Checks all buffer lengths before writing output.
    #[allow(clippy::too_many_arguments)]
    pub fn external_product_to<Table: FftTable>(
        &self,
        input: &[T],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
    ) {
        self.product_to::<_, false>(input, output, fft, ordinary, split);
    }
    /// Adds the split product to an existing coefficient accumulator.
    /// Inherits [`Self::external_product_to`]'s contracts and checks.
    pub fn external_product_add_assign<Table: FftTable>(
        &self,
        input: &[T],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
    ) {
        self.product_to::<_, true>(input, output, fft, ordinary, split);
    }
    // ADD retains the original accumulator. Digits are dead after accumulation,
    // so their coefficient buffer holds the low inverse without another allocation.
    fn product_to<Table: FftTable, const ADD: bool>(
        &self,
        input: &[T],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
    ) {
        self.check_product(input, output, fft, ordinary, split);
        let mut w = ordinary.as_mut();
        w.fourier_accumulator.set_zero();
        split.high_spectrum.fill(Complex64::default());
        self.basis.init_carry_slice(input, w.carries);
        let rows = FourierPolynomialIter::new(&self.low, self.n.fourier_poly_len()).zip(
            FourierPolynomialIter::new(&self.high, self.n.fourier_poly_len()),
        );
        for (decomposer, (low, high)) in self.basis.decomposer_iter().zip(rows) {
            decomposer.decompose_slice_to(input, w.decomposed_poly, w.carries);
            fft.forward_as_integer(w.decomposed_poly, w.decomposed_fourier);
            FourierPolynomial(w.fourier_accumulator.as_mut())
                .add_mul_assign(&FourierPolynomial(&*w.decomposed_fourier), &low);
            FourierPolynomial(&mut *split.high_spectrum)
                .add_mul_assign(&FourierPolynomial(&*w.decomposed_fourier), &high);
        }
        self.finish_product::<_, ADD>(output, fft, ordinary, split);
    }
    /// Validate complete public product resources before any output writes.
    fn check_product<Table: FftTable>(
        &self,
        input: &[T],
        output: &[T],
        fft: &FftEngine<'_, Table>,
        ordinary: &FourierNtruExternalProductWorkspace<T>,
        split: &FourierNtruSplitWorkspace<T>,
    ) {
        assert_eq!(input.len(), self.n.get(), "split input length mismatch");
        assert_eq!(output.len(), self.n.get(), "split output length mismatch");
        assert_eq!(fft.poly_length(), self.n, "split FFT mismatch");
        assert_eq!(ordinary.poly_length(), self.n, "split workspace mismatch");
        assert_eq!(
            split.high_product.len(),
            self.n.get(),
            "split extension mismatch"
        );
    }
    /// Round limbs independently; the digit coefficient buffer is dead here.
    fn finish_product<Table: FftTable, const ADD: bool>(
        &self,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
    ) {
        let w = ordinary.as_mut();
        fft.backward_as_torus(w.fourier_accumulator.as_ref(), w.decomposed_poly);
        fft.backward_as_torus(&split.high_spectrum, &mut split.high_product);
        for ((out, &low), &high) in output
            .iter_mut()
            .zip(w.decomposed_poly.iter())
            .zip(split.high_product.iter())
        {
            let product = low.wrapping_add(high << self.low_bits);
            *out = if ADD {
                out.wrapping_add(product)
            } else {
                product
            };
        }
    }
}

/// A split gadget with inverse-permuted limbs and its forward automorphism map.
/// Owns only the cross branch; the identity gadget is borrowed at evaluation.
/// Signed Fourier limbs must not be converted back and canonically re-split.
pub struct FourierNtruSplitAutomorphism<T: TorusFftValue> {
    cross: FourierNtruSplitGadget<T>,
    map: Vec<(usize, bool)>,
}
impl<T: TorusFftValue> FourierNtruSplitAutomorphism<T> {
    /// Moves the cross gadget into inverse-permuted representation using its FFT table.
    /// # Panics
    /// Requires an odd degree below 2N and matching polynomial length.
    /// # Correctness
    /// `table` must be the exact table used to generate the gadget.
    #[must_use]
    pub fn new<Table: FftTable>(
        mut cross: FourierNtruSplitGadget<T>,
        degree: usize,
        table: &Table,
    ) -> Self {
        assert_eq!(
            table.poly_length(),
            cross.n,
            "split automorphism FFT mismatch"
        );
        assert!(
            degree & 1 == 1 && degree < 2 * cross.n.get(),
            "split automorphism degree must be odd and below 2N"
        );
        let map = table.automorphism_map(degree);
        let h = cross.n.fourier_poly_len();
        let mut scratch = vec![Complex64::default(); h];
        for limb in [&mut cross.low, &mut cross.high] {
            for mut row in FourierPolynomialIterMut::new(limb, h) {
                // Invert the destination-to-source map, including conjugation.
                for (dst, &(src, conjugate)) in map.iter().enumerate() {
                    let value = row.as_ref()[dst];
                    scratch[src] = if conjugate { value.conj() } else { value };
                }
                row.as_mut().copy_from_slice(&scratch);
            }
        }
        Self { cross, map }
    }
    /// Computes sum_j D_j(input)*identity_j + sigma(D_j(input))*cross_j.
    /// Decomposes/FFTs each digit once, restores the cross branch only after the
    /// complete inner product, then inverse-rounds the summed low/high limbs.
    /// `branches` contains exactly N complex values and is overwritten on reuse.
    /// # Correctness
    /// Inherits [`FourierNtruSplitGadget::external_product_to`]'s numeric and FFT
    /// contracts. Both gadgets must share the intended secret and interpretation.
    /// The sum adds limb error; a high-limb error of one is amplified by 2^b.
    /// # Panics
    /// Checks matching gadgets and complete resources before output writes.
    #[allow(clippy::too_many_arguments)]
    pub fn external_product_sum_to<Table: FftTable>(
        &self,
        identity: &FourierNtruSplitGadget<T>,
        input: &[T],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
        branches: &mut [Complex64],
    ) {
        assert!(
            identity.compatible(&self.cross),
            "split automorphism gadget mismatch"
        );
        identity.check_product(input, output, fft, ordinary, split);
        let h = identity.n.fourier_poly_len();
        assert_eq!(
            branches.len(),
            identity.n.get(),
            "split branch scratch mismatch"
        );
        let (branch_low, branch_high) = branches.split_at_mut(h);
        branch_low.fill(Complex64::default());
        branch_high.fill(Complex64::default());
        let mut w = ordinary.as_mut();
        w.fourier_accumulator.set_zero();
        split.high_spectrum.fill(Complex64::default());
        identity.basis.init_carry_slice(input, w.carries);
        let identity_rows = FourierPolynomialIter::new(&identity.low, h)
            .zip(FourierPolynomialIter::new(&identity.high, h));
        let cross_rows = FourierPolynomialIter::new(&self.cross.low, h)
            .zip(FourierPolynomialIter::new(&self.cross.high, h));
        for (decomposer, ((low, high), (cross_low, cross_high))) in identity
            .basis
            .decomposer_iter()
            .zip(identity_rows.zip(cross_rows))
        {
            decomposer.decompose_slice_to(input, w.decomposed_poly, w.carries);
            fft.forward_as_integer(w.decomposed_poly, w.decomposed_fourier);
            let digit = FourierPolynomial(&*w.decomposed_fourier);
            FourierPolynomial(w.fourier_accumulator.as_mut()).add_mul_assign(&digit, &low);
            FourierPolynomial(&mut *split.high_spectrum).add_mul_assign(&digit, &high);
            FourierPolynomial(&mut *branch_low).add_mul_assign(&digit, &cross_low);
            FourierPolynomial(&mut *branch_high).add_mul_assign(&digit, &cross_high);
        }
        for (dst, &(src, conjugate)) in self.map.iter().enumerate() {
            let low = branch_low[src];
            let high = branch_high[src];
            w.fourier_accumulator.as_mut()[dst] += if conjugate { low.conj() } else { low };
            split.high_spectrum[dst] += if conjugate { high.conj() } else { high };
        }
        identity.finish_product::<_, false>(output, fft, ordinary, split);
    }

    /// Sums automorphism external products using a single digit decomposition and FFT.
    /// An optional unpermuted identity gadget contributes to the same limb sum.
    /// With no identity, only the cross products are returned: a trace caller must
    /// add its separately normalized input afterward.
    ///
    /// Each cross branch accumulates in inverse-permuted coordinates before its
    /// forward automorphism is added to the common accumulator. Both limbs are
    /// inverse-rounded once, after all branches; no intermediate torus conversion
    /// or re-splitting is performed. `branches` has exactly `cross.len() * N`
    /// complex entries (one low/high pair per branch), overwritten on every call.
    ///
    /// # Correctness
    /// Inherits [`Self::external_product_sum_to`]'s numeric and table contracts.
    /// The caller supplies keys for the intended automorphisms and messages; this
    /// routine does not normalize the input or establish a trace subgroup. More
    /// branches increase accumulated FFT error; budget the high limb separately.
    ///
    /// # Panics
    /// Requires at least one cross key, compatible bases/limb widths/lengths,
    /// and exact input, output and scratch lengths, checked before output writes.
    #[allow(clippy::too_many_arguments)]
    pub fn external_products_sum_to<Table: FftTable>(
        cross: &[Self],
        identity: Option<&FourierNtruSplitGadget<T>>,
        input: &[T],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
        branches: &mut [Complex64],
    ) {
        let reference = Self::check_branches(cross, branches);
        assert!(
            identity.is_none_or(|key| reference.compatible(key)),
            "split identity gadget mismatch"
        );
        reference.check_product(input, output, fft, ordinary, split);
        Self::accumulate_products(cross, identity, input, fft, ordinary, split, branches);
        let mut w = ordinary.as_mut();
        for (key, branch) in cross.iter().zip(branches.chunks_exact(input.len())) {
            key.restore_branch::<true>(
                branch,
                w.fourier_accumulator.as_mut(),
                &mut split.high_spectrum,
            );
        }
        reference.finish_product::<_, false>(output, fft, ordinary, split);
    }

    /// Computes each automorphism external product separately, sharing decomposition
    /// and digit FFTs. Outputs are coefficient polynomials in cross-key order.
    /// `output` has exactly `cross.len()*N` torus words; `branches` has the same
    /// number of complex values, holding low/high spectra for each branch.
    /// Both are overwritten, with no online allocation.
    ///
    /// Unlike [`Self::external_products_sum_to`], this inverse-rounds each branch's
    /// limbs independently. Summing these outputs need not equal inverse-rounding
    /// a summed spectrum. Callers must budget each low/high error, including the
    /// factor 2^b on high-limb error and correlations when reusing a result.
    ///
    /// # Correctness
    /// Inherits [`Self::external_products_sum_to`]'s representation, numeric and
    /// FFT-table contracts. No normalization or trace projection is performed.
    /// # Panics
    /// Requires nonempty compatible keys and exact input/output/scratch lengths,
    /// checked before writing any output.
    #[allow(clippy::too_many_arguments)]
    pub fn external_products_to<Table: FftTable>(
        cross: &[Self],
        input: &[T],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
        branches: &mut [Complex64],
    ) {
        let reference = Self::check_branches(cross, branches);
        assert_eq!(
            output.len(),
            branches.len(),
            "split product batch length mismatch"
        );
        let n = reference.n.get();
        reference.check_product(input, &output[..n], fft, ordinary, split);
        Self::accumulate_products(cross, None, input, fft, ordinary, split, branches);
        for ((key, branch), mut output) in cross
            .iter()
            .zip(branches.chunks_exact(n))
            .zip(crate::ntru::NtruIterMut::new(output, n))
        {
            let mut w = ordinary.as_mut();
            key.restore_branch::<false>(
                branch,
                w.fourier_accumulator.as_mut(),
                &mut split.high_spectrum,
            );
            reference.finish_product::<_, false>(output.as_mut(), fft, ordinary, split);
        }
    }

    /// Establishes the common branch layout once at each public batch boundary.
    fn check_branches<'a>(
        cross: &'a [Self],
        branches: &[Complex64],
    ) -> &'a FourierNtruSplitGadget<T> {
        let reference = &cross
            .first()
            .expect("split products require a cross key")
            .cross;
        assert!(
            cross.iter().all(|key| reference.compatible(&key.cross)),
            "split automorphism gadget mismatch"
        );
        let n = reference.n.get();
        assert_eq!(
            branches.len() / n,
            cross.len(),
            "split branch count mismatch"
        );
        assert_eq!(branches.len() & (n - 1), 0, "split branch scratch mismatch");
        reference
    }

    /// Keeps all branch inner products in inverse-permuted coordinates, so one
    /// digit transform serves every key. Public callers already checked resources.
    fn accumulate_products<Table: FftTable>(
        cross: &[Self],
        identity: Option<&FourierNtruSplitGadget<T>>,
        input: &[T],
        fft: &mut FftEngine<'_, Table>,
        ordinary: &mut FourierNtruExternalProductWorkspace<T>,
        split: &mut FourierNtruSplitWorkspace<T>,
        branches: &mut [Complex64],
    ) {
        let reference = &cross[0].cross;
        let n = reference.n.get();
        let h = reference.n.fourier_poly_len();
        branches.fill(Complex64::default());
        let mut w = ordinary.as_mut();
        w.fourier_accumulator.set_zero();
        split.high_spectrum.fill(Complex64::default());
        reference.basis.init_carry_slice(input, w.carries);
        for (level, decomposer) in reference.basis.decomposer_iter().enumerate() {
            decomposer.decompose_slice_to(input, w.decomposed_poly, w.carries);
            fft.forward_as_integer(w.decomposed_poly, w.decomposed_fourier);
            let digit = FourierPolynomial(&*w.decomposed_fourier);
            let rows = level * h..(level + 1) * h;
            if let Some(identity) = identity {
                FourierPolynomial(w.fourier_accumulator.as_mut())
                    .add_mul_assign(&digit, &FourierPolynomial(&identity.low[rows.clone()]));
                FourierPolynomial(&mut *split.high_spectrum)
                    .add_mul_assign(&digit, &FourierPolynomial(&identity.high[rows.clone()]));
            }
            for (key, scratch) in cross.iter().zip(branches.chunks_exact_mut(n)) {
                let (low, high) = scratch.split_at_mut(h);
                FourierPolynomial(low)
                    .add_mul_assign(&digit, &FourierPolynomial(&key.cross.low[rows.clone()]));
                FourierPolynomial(high)
                    .add_mul_assign(&digit, &FourierPolynomial(&key.cross.high[rows.clone()]));
            }
        }
    }

    /// Restore the automorphism after the complete inner product, either adding
    /// to a shared spectrum or overwriting it for an independent limb inverse.
    fn restore_branch<const ADD: bool>(
        &self,
        branch: &[Complex64],
        low_out: &mut [Complex64],
        high_out: &mut [Complex64],
    ) {
        let (low, high) = branch.split_at(low_out.len());
        for (dst, &(src, conjugate)) in self.map.iter().enumerate() {
            let low = if conjugate { low[src].conj() } else { low[src] };
            let high = if conjugate {
                high[src].conj()
            } else {
                high[src]
            };
            if ADD {
                low_out[dst] += low;
                high_out[dst] += high;
            } else {
                low_out[dst] = low;
                high_out[dst] = high;
            }
        }
    }
}
