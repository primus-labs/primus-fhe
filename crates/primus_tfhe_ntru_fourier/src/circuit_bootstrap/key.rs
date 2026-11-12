//! Optional trace and scheme-switch material under the accumulator secret.

use primus_fft::{FftTable, TorusFftValue};
use primus_ntru::{FourierNtruSchemeSwitchKey, FourierNtruSecretKey, FourierNtruTraceKey};

use crate::{KeyGenerator, TfheContext, circuit_bootstrap::CbsGadgetParameters};

/// Additional keys for NTRU CBS; BR material is owned by [`crate::key::BlindRotationKey`].
/// All projection material uses the accumulator secret, not the post-PBS client secret.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`FourierNtruSchemeSwitchKey`].
///
/// # FusedLastStage noise
///
/// Let c be the ciphertext after the trace prefix and Pi2 retain even
/// coefficients. Use the SS basis: a=floor(c/2), r=c-2a and
/// a=sum(g_j*d_j)+epsilon. The exact
/// terminal phase is f*Pi2(f*c)-f*Pi2(f*r)-2*f*Pi2(f*epsilon)
/// +sum(d_j*eta_id,j + gamma(d_j)*eta_cross,j), gamma=sigma_(N+1).
/// The two key row phases are g_j*f^2+eta_id,j and g_j*f*gamma(f)+eta_cross,j.
/// Thus fusion changes rounding/decomposition noise; it does not promise a
/// smaller error than Separate. Low/high inverse errors and the final ordinary
/// Fourier conversion must also be budgeted before a consuming CMux.
///
/// # PairedTrace noise and storage
///
/// A trace pair uses a=floor(c/4) and S=I+alpha+beta+alpha*beta. Its cross
/// branches gamma in {alpha, beta, alpha*beta} have phase g_j*gamma(f)+eta. For
/// a=sum(g_j*d_j)+epsilon, its phase modulo 2^64 is
/// S(f*c)/4 - S(f*(c-4a))/4 - (S-I)(f*epsilon)
/// +sum_gamma,j gamma(d_j)*eta_gamma,j, with integer lifts retained through
/// division. This prefix S is not generally a coefficient projection.
/// The terminal R4/R8 block uses the SS basis and S=R*Pi_R; its
/// keys gamma in {sigma_(1+i*2N/R) : 0<=i<R} have phase g_j*f*gamma(f)+eta.
/// Its output phase is f*Pi_R(f*c)-f*Pi_R(f*(c-Ra))-R*f*Pi_R(f*epsilon)
/// +sum_gamma,j gamma(d_j)*eta_gamma,j. These expressions do not imply
/// independent errors across stages or selectors, nor a certified failure rate.
/// Each low/high inverse contributes delta_low+2^b*delta_high to the ciphertext.
///
/// Paired NGSW output retains the full binary trace for NLEV/dual consumers,
/// adds three inverse-permuted keys per pair and R-1 terminal keys, and reuses
/// one branch buffer sized for the terminal block. Even log2(N) ends in R4;
/// odd log2(N) ends in R8. No online keys or buffers are allocated.
///
/// One-hot NGSW batches additionally cache `[floor(c/4), v3, v5, v15]` in 4*N
/// torus words, without extra keys. Each target k rotates these components by
/// k, 3k, 5k, 15k before completing the remaining pairs and terminal SS. This
/// shares the first decomposition and three independently inverse-rounded
/// products. The first remainder becomes X^k(c mod 4), which may be signed;
/// the full suffix removes the differing native Q/4 lifts. The intermediate
/// cache is not itself a projection. Shared product/FFT errors are correlated
/// across targets; independent-target failure bounds cannot be assumed.
/// Ordinary CBS owns no such cache and retains per-row paired projection.
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    parameters: CbsGadgetParameters<T>,
    trace: TraceMaterial<T>,
    scheme_switch: SchemeSwitchMaterial<T>,
    precision: crate::FourierCbsPrecision,
    projection: ProjectionMaterial<T>,
}

/// Additional NGSW-only material. Full binary trace keys remain in `trace` for
/// NLEV/dual output; the existing SSK supplies every terminal identity branch.
enum ProjectionMaterial<T: TorusFftValue> {
    Separate,
    LastStage(primus_ntru::FourierNtruSplitAutomorphism<T>),
    Paired {
        // Online order: sigma_(1+2^(j+1)), sigma_(1+2^(j+2)), and their product.
        pairs: Vec<[primus_ntru::FourierNtruSplitAutomorphism<T>; 3]>,
        // R4 for even logN, R8 for odd logN; contains only nonidentity branches.
        terminal: Vec<primus_ntru::FourierNtruSplitAutomorphism<T>>,
    },
}
impl<T: TorusFftValue> ProjectionMaterial<T> {
    fn branch_count(&self) -> usize {
        match self {
            Self::Separate => 0,
            Self::LastStage(_) => 1,
            Self::Paired { terminal, .. } => terminal.len(),
        }
    }
}

/// Per-evaluator projection storage, reused for every selector and output row.
/// Separate owns no branch spectra. NLEV/dual can reuse the same coefficient buffers.
pub(super) struct ProjectionWorkspace<T: TorusFftValue> {
    pub(super) scratch: Vec<T>,
    pub(super) projected: primus_ntru::NlevCiphertext<Vec<T>>,
    branches: Vec<primus_fft::Complex64>,
}
impl<T: TorusFftValue> ProjectionWorkspace<T> {
    pub(super) fn new(key: &CircuitBootstrapKey<T>) -> Self {
        let n = key.parameters.poly_length().get();
        Self {
            scratch: vec![T::ZERO; 2 * n],
            projected: primus_ntru::NlevCiphertext::zero(key.parameters.output_nlev_len()),
            branches: vec![primus_fft::Complex64::default(); key.projection.branch_count() * n],
        }
    }
}

/// First-pair components [floor(c/4), v3, v5, v15] for one common BR result.
/// Only one-hot PairedTrace owns this cache. It is overwritten before each batch;
/// neither a component nor their sum is a completed trace projection.
pub(super) struct SharedTracePair<T> {
    coefficients: Box<[T]>,
}
impl<T: TorusFftValue> SharedTracePair<T> {
    pub(super) fn new(key: &CircuitBootstrapKey<T>) -> Option<Self> {
        matches!(key.projection, ProjectionMaterial::Paired { .. }).then(|| Self {
            coefficients: vec![T::ZERO; 4 * key.parameters.poly_length().get()].into_boxed_slice(),
        })
    }
}

/// Each stage owns only its selected representation. The two choices are independent.
enum TraceMaterial<T: TorusFftValue> {
    Ordinary(FourierNtruTraceKey<T>),
    Split(
        Vec<(
            primus_poly::CoeffAutomorphismPermutation,
            primus_ntru::FourierNtruSplitGadget<T>,
        )>,
    ),
}
/// SS converts split products back to ordinary Fourier output for all consumers.
enum SchemeSwitchMaterial<T: TorusFftValue> {
    Ordinary(FourierNtruSchemeSwitchKey<T>),
    Split(primus_ntru::FourierNtruSplitGadget<T>),
}

impl<T: TorusFftValue> CircuitBootstrapKey<T> {
    /// Checks the key's fixed CBS parameters before preparing LUTs or buffers.
    /// NTRU cannot substitute a different output basis; compatibility does not
    /// establish actual secret or transform identity.
    pub(super) fn check_parameters<Table: FftTable, LM: primus_reduce::RingContext<T>>(
        &self,
        context: &TfheContext<T, Table, LM>,
    ) -> Result<(), crate::TfheEvaluationError> {
        if !self.parameters.is_compatible(context.parameters()) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if context.cbs_parameters().map_or(
            self.precision != crate::FourierCbsPrecision::ORDINARY,
            |parameters| !self.is_compatible(parameters),
        ) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }
        Ok(())
    }

    /// Matches the configured projection and gadget decomposition; the evaluator separately
    /// validates its accumulator domain. NTRU scheme switching fixes the output basis.
    pub(crate) fn is_compatible<LM: primus_reduce::RingContext<T>>(
        &self,
        operation: &crate::CbsParameters<T, LM>,
    ) -> bool {
        let parameters = operation.gadget();
        self.precision == operation.fourier_precision()
            && self.projection_method() == operation.projection()
            && self.parameters.output_basis() == parameters.output_basis()
            && self.parameters.trace().basis() == parameters.trace().basis()
            && self.parameters.scheme_switch().basis() == parameters.scheme_switch().basis()
    }

    /// Returns the NGSW-only algorithm bound to this material.
    #[must_use]
    pub fn projection_method(&self) -> crate::NtruProjectionMethod {
        match self.projection {
            ProjectionMaterial::Separate => crate::NtruProjectionMethod::Separate,
            ProjectionMaterial::LastStage(_) => crate::NtruProjectionMethod::FusedLastStage,
            ProjectionMaterial::Paired { .. } => crate::NtruProjectionMethod::PairedTrace,
        }
    }

    /// Returns the gadget parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CbsGadgetParameters<T> {
        &self.parameters
    }

    /// Borrows ordinary reverse-trace material; split keys have no ordinary view.
    #[must_use]
    pub fn trace_key(&self) -> Option<&FourierNtruTraceKey<T>> {
        match &self.trace {
            TraceMaterial::Ordinary(trace) => Some(trace),
            _ => None,
        }
    }

    /// Borrows ordinary NLEV-to-NGSW material; split keys have no ordinary view.
    #[must_use]
    pub fn scheme_switch_key(&self) -> Option<&FourierNtruSchemeSwitchKey<T>> {
        match &self.scheme_switch {
            SchemeSwitchMaterial::Ordinary(scheme_switch) => Some(scheme_switch),
            _ => None,
        }
    }
    /// Projects the full prefix, including general nonzero message tails. The owning
    /// evaluator established layouts; native halving is floor(c/2), not modular inverse.
    pub(super) fn project<Table: FftTable>(
        &self,
        input: primus_ntru::NtruCiphertext<&[T]>,
        output: &mut [T],
        fft: &mut primus_fft::FftEngine<'_, Table>,
        scratch: &mut [T],
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: Option<&mut primus_ntru::FourierNtruSplitWorkspace<T>>,
    ) {
        self.project_prefix::<_, false>(input, output, fft, scratch, ordinary, split);
    }
    /// NGSW fusion omits only sigma_(N+1); NLEV/dual retain every trace stage.
    fn project_prefix<Table: FftTable, const SKIP_LAST: bool>(
        &self,
        input: primus_ntru::NtruCiphertext<&[T]>,
        output: &mut [T],
        fft: &mut primus_fft::FftEngine<'_, Table>,
        scratch: &mut [T],
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: Option<&mut primus_ntru::FourierNtruSplitWorkspace<T>>,
    ) {
        match &self.trace {
            TraceMaterial::Ordinary(trace) => trace.project_prefix_coefficients_with_scratch_to(
                &input,
                output.len() / self.parameters.poly_length().get(),
                output,
                fft,
                scratch,
                ordinary,
            ),
            TraceMaterial::Split(trace) => {
                let split = split.expect("split extension bound with BR resources");
                let n = self.parameters.poly_length().get();
                let (product, permuted) = scratch.split_at_mut(n);
                for (index, mut row) in
                    primus_lattice::ntru::NtruIterMut::new(output, n).enumerate()
                {
                    input.mul_monomial_to(
                        index.wrapping_neg() & (2 * n - 1),
                        &mut row,
                        primus_modulus::NativeModulus::new(),
                    );
                    for (permutation, key) in trace
                        .iter()
                        .rev()
                        .take(trace.len() - usize::from(SKIP_LAST))
                    {
                        for x in row.as_mut() {
                            *x >>= 1u32;
                        }
                        permutation.apply_to(
                            row.as_ref(),
                            permuted,
                            primus_modulus::NativeModulus::new(),
                        );
                        key.external_product_to(permuted, product, fft, ordinary, split);
                        for (x, &v) in row.as_mut().iter_mut().zip(product.iter()) {
                            *x = x.wrapping_add(v);
                        }
                    }
                }
            }
        }
    }
    /// Produces ordinary Fourier NGSW; only this output may use terminal fusion.
    pub(super) fn project_ngsw<Table: FftTable>(
        &self,
        input: primus_ntru::NtruCiphertext<&[T]>,
        output: &mut [primus_fft::Complex64],
        workspace: &mut ProjectionWorkspace<T>,
        fft: &mut primus_fft::FftEngine<'_, Table>,
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        mut split: Option<&mut primus_ntru::FourierNtruSplitWorkspace<T>>,
    ) {
        if let ProjectionMaterial::Separate = self.projection {
            self.project(
                input,
                workspace.projected.as_mut(),
                fft,
                &mut workspace.scratch,
                ordinary,
                split.as_deref_mut(),
            );
            self.switch(
                workspace.projected.as_ref(),
                output,
                fft,
                &mut workspace.scratch,
                ordinary,
                split,
            );
            return;
        }
        match &self.projection {
            ProjectionMaterial::LastStage(_) => self.project_prefix::<_, true>(
                input,
                workspace.projected.as_mut(),
                fft,
                &mut workspace.scratch,
                ordinary,
                split.as_deref_mut(),
            ),
            ProjectionMaterial::Paired { pairs, .. } => self.project_paired_prefix(
                pairs,
                input,
                workspace,
                fft,
                ordinary,
                split
                    .as_deref_mut()
                    .expect("paired projection requires split resources"),
            ),
            ProjectionMaterial::Separate => unreachable!("separate projection returned above"),
        }
        self.finish_fused_projection(
            output,
            workspace,
            fft,
            ordinary,
            split.expect("split extension bound with BR resources"),
        );
    }

    /// Completes the terminal subgroup in the SS basis for both projection routes.
    fn finish_fused_projection<Table: FftTable>(
        &self,
        output: &mut [primus_fft::Complex64],
        workspace: &mut ProjectionWorkspace<T>,
        fft: &mut primus_fft::FftEngine<'_, Table>,
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: &mut primus_ntru::FourierNtruSplitWorkspace<T>,
    ) {
        let SchemeSwitchMaterial::Split(identity) = &self.scheme_switch else {
            unreachable!("fused configuration requires split SS")
        };
        let n = self.parameters.poly_length().get();
        let product = &mut workspace.scratch[..n];
        let mut output = primus_ntru::FourierNgswCiphertext::new(output);
        let terminal_bits = (self.projection.branch_count() + 1).ilog2();
        for (mut row, mut dest) in workspace
            .projected
            .iter_ntru_mut(n)
            .zip(output.iter_ntru_mut(n / 2))
        {
            // Native unsigned floor, once per fused block, before SS decomposition.
            for value in row.as_mut() {
                *value >>= terminal_bits;
            }
            match &self.projection {
                ProjectionMaterial::LastStage(cross) => cross.external_product_sum_to(
                    identity,
                    row.as_ref(),
                    product,
                    fft,
                    ordinary,
                    split,
                    &mut workspace.branches,
                ),
                ProjectionMaterial::Paired { terminal, .. } => {
                    primus_ntru::FourierNtruSplitAutomorphism::external_products_sum_to(
                        terminal,
                        Some(identity),
                        row.as_ref(),
                        product,
                        fft,
                        ordinary,
                        split,
                        &mut workspace.branches,
                    )
                }
                ProjectionMaterial::Separate => unreachable!("separate projection returned above"),
            }
            // Consumers use ordinary Fourier controls; this conversion is required.
            fft.forward_as_torus(product, dest.as_mut());
        }
    }

    /// Each pair keeps floor(c/4) as identity and adds three hoisted cross products.
    /// Rounding/decomposition occurs once per pair, so this is not bit-identical to
    /// two binary stages. The terminal subgroup is handled separately in the SS basis.
    fn project_paired_prefix<Table: FftTable>(
        &self,
        pairs: &[[primus_ntru::FourierNtruSplitAutomorphism<T>; 3]],
        input: primus_ntru::NtruCiphertext<&[T]>,
        workspace: &mut ProjectionWorkspace<T>,
        fft: &mut primus_fft::FftEngine<'_, Table>,
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: &mut primus_ntru::FourierNtruSplitWorkspace<T>,
    ) {
        let n = self.parameters.poly_length().get();
        let product = &mut workspace.scratch[..n];
        let branches = &mut workspace.branches[..3 * n];
        for (index, mut row) in workspace.projected.iter_ntru_mut(n).enumerate() {
            input.mul_monomial_to(
                index.wrapping_neg() & (2 * n - 1),
                &mut row,
                primus_modulus::NativeModulus::new(),
            );
            Self::apply_trace_pairs(pairs, row.as_mut(), product, branches, fft, ordinary, split);
        }
    }

    /// Prepare each branch once. Floor before rotation selects a common integer
    /// lift; each target has signed remainder X^k(c mod 4), not unsigned low bits.
    /// Each branch is inverse-rounded separately, unlike the ordinary pair sum.
    /// The cache must be regenerated for every BR input; only a complete trace+SS
    /// suffix consumes these components correctly.
    pub(super) fn prepare_shared_pair<Table: FftTable>(
        &self,
        input: &[T],
        prepared: &mut SharedTracePair<T>,
        workspace: &mut ProjectionWorkspace<T>,
        fft: &mut primus_fft::FftEngine<'_, Table>,
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: &mut primus_ntru::FourierNtruSplitWorkspace<T>,
    ) {
        let ProjectionMaterial::Paired { pairs, .. } = &self.projection else {
            unreachable!("cache allocated only for paired trace")
        };
        let n = self.parameters.poly_length().get();
        let (normalized, products) = prepared.coefficients.split_at_mut(n);
        for (a, &c) in normalized.iter_mut().zip(input) {
            *a = c >> 2u32;
        }
        primus_ntru::FourierNtruSplitAutomorphism::external_products_to(
            &pairs[0],
            normalized,
            products,
            fft,
            ordinary,
            split,
            &mut workspace.branches[..3 * n],
        );
    }

    /// Targets k=selector*stride-level use shifts k,3k,5k,15k. Rotating the pair
    /// sum only once would be incorrect. Rotated digits may be noncanonical
    /// (+B/2), but their residual rotates exactly. The common native lift can
    /// differ by Q/4 from per-target floor: only the full suffix removes it,
    /// via P_(j+2) S_j=4 P_j, retaining the signed low-two-bit remainder.
    /// Reused branch errors are correlated across targets and branches; this is
    /// not a claim of unchanged noise or a certified failure probability.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn project_shared_ngsw<Table: FftTable>(
        &self,
        selector_shift: usize,
        prepared: &SharedTracePair<T>,
        output: &mut [primus_fft::Complex64],
        workspace: &mut ProjectionWorkspace<T>,
        fft: &mut primus_fft::FftEngine<'_, Table>,
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: &mut primus_ntru::FourierNtruSplitWorkspace<T>,
    ) {
        let ProjectionMaterial::Paired { pairs, .. } = &self.projection else {
            unreachable!("cache allocated only for paired trace")
        };
        let n = self.parameters.poly_length().get();
        let modulus = primus_modulus::NativeModulus::new();
        let product = &mut workspace.scratch[..n];
        for (level, mut row) in workspace.projected.iter_ntru_mut(n).enumerate() {
            let shift = selector_shift.wrapping_sub(level) & (2 * n - 1);
            let (a, products) = prepared.coefficients.split_at(n);
            primus_ntru::NtruCiphertext::new(a).mul_monomial_to(shift, &mut row, modulus);
            for (degree, branch) in [3, 5, 15]
                .into_iter()
                .zip(primus_lattice::ntru::NtruIter::new(products, n))
            {
                branch.mul_monomial_to(
                    (degree * shift) & (2 * n - 1),
                    &mut primus_ntru::NtruCiphertext::new(&mut *product),
                    modulus,
                );
                for (x, &y) in row.as_mut().iter_mut().zip(product.iter()) {
                    *x = x.wrapping_add(y);
                }
            }
            Self::apply_trace_pairs(
                &pairs[1..],
                row.as_mut(),
                product,
                &mut workspace.branches[..3 * n],
                fft,
                ordinary,
                split,
            );
        }
        self.finish_fused_projection(output, workspace, fft, ordinary, split);
    }

    /// Each independent suffix keeps the same normalization, digit order and
    /// summed inverse as ordinary paired projection; only the first pair differs.
    fn apply_trace_pairs<Table: FftTable>(
        pairs: &[[primus_ntru::FourierNtruSplitAutomorphism<T>; 3]],
        row: &mut [T],
        product: &mut [T],
        branches: &mut [primus_fft::Complex64],
        fft: &mut primus_fft::FftEngine<'_, Table>,
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: &mut primus_ntru::FourierNtruSplitWorkspace<T>,
    ) {
        for keys in pairs {
            for value in row.iter_mut() {
                *value >>= 2u32;
            }
            primus_ntru::FourierNtruSplitAutomorphism::external_products_sum_to(
                keys, None, row, product, fft, ordinary, split, branches,
            );
            for (value, &addend) in row.iter_mut().zip(product.iter()) {
                *value = value.wrapping_add(addend);
            }
        }
    }

    /// Split SS rounds two limbs independently, reconstructs coefficient NGSW,
    /// then forwards once to the ordinary representation used by LUT CMux.
    /// Trace scratch is dead and its first N coefficients hold this product.
    pub(super) fn switch<Table: FftTable>(
        &self,
        input: &[T],
        output: &mut [primus_fft::Complex64],
        fft: &mut primus_fft::FftEngine<'_, Table>,
        scratch: &mut [T],
        ordinary: &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
        split: Option<&mut primus_ntru::FourierNtruSplitWorkspace<T>>,
    ) {
        match &self.scheme_switch {
            SchemeSwitchMaterial::Ordinary(scheme_switch) => scheme_switch.apply_to(
                &primus_ntru::NlevCiphertext::new(input),
                &mut primus_ntru::FourierNgswCiphertext::new(output),
                fft,
                ordinary,
            ),
            SchemeSwitchMaterial::Split(scheme_switch) => {
                let split = split.expect("split extension bound with BR resources");
                let n = self.parameters.poly_length().get();
                let product = &mut scratch[..n];
                let input = primus_ntru::NlevCiphertext::new(input);
                let mut output = primus_ntru::FourierNgswCiphertext::new(output);
                for (row, mut dest) in input.iter_ntru(n).zip(output.iter_ntru_mut(n / 2)) {
                    scheme_switch.external_product_to(row.as_ref(), product, fft, ordinary, split);
                    fft.forward_as_torus(product, dest.as_mut());
                }
            }
        }
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Ordinary stages retain direct Fourier generation; split stages share the
    /// one exact inverse already prepared for this bundle. Dispatch only at setup.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        transformed: &FourierNtruSecretKey,
        generator: Option<&primus_ntru::split::NativeNtruGadgetGenerator<T>>,
        operation: &crate::CbsParameters<T, LM>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T> {
        let parameters = operation.gadget();
        let precision = operation.fourier_precision();
        let trace = match precision.trace {
            crate::FourierPrecision::Ordinary => {
                TraceMaterial::Ordinary(FourierNtruTraceKey::generate(
                    secret,
                    transformed,
                    parameters.trace(),
                    &mut self.fft,
                    rng,
                    &mut self.gadget,
                ))
            }
            crate::FourierPrecision::Split { low_bits } => {
                let generator = generator.expect("split generation prepared once for bundle");
                let n = parameters.poly_length();
                TraceMaterial::Split(
                    (0..n.log_n())
                        .map(|i| {
                            let degree = (n.get() >> i) + 1;
                            (
                                primus_poly::CoeffAutomorphismPermutation::new(degree, n),
                                generator.encrypt_automorphism(
                                    degree,
                                    parameters.trace(),
                                    low_bits,
                                    &mut self.fft,
                                    rng,
                                ),
                            )
                        })
                        .collect(),
                )
            }
        };
        let scheme_switch = match precision.scheme_switch {
            crate::FourierPrecision::Ordinary => {
                SchemeSwitchMaterial::Ordinary(FourierNtruSchemeSwitchKey::generate(
                    secret,
                    transformed,
                    parameters.output_basis(),
                    parameters.scheme_switch(),
                    &mut self.fft,
                    rng,
                    &mut self.gadget,
                ))
            }
            crate::FourierPrecision::Split { low_bits } => SchemeSwitchMaterial::Split(
                generator
                    .expect("split generation prepared once for bundle")
                    .encrypt_scheme_switch(
                        parameters.scheme_switch(),
                        low_bits,
                        &mut self.fft,
                        rng,
                    ),
            ),
        };
        let projection = self.generate_projection_material(&trace, generator, operation, rng);
        CircuitBootstrapKey {
            parameters: parameters.clone(),
            precision,
            trace,
            scheme_switch,
            projection,
        }
    }

    /// Generates only the selected NGSW projection branches after the common keys.
    /// The SSK identity is borrowed online; no duplicate R2 terminal is retained.
    fn generate_projection_material<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        trace: &TraceMaterial<T>,
        generator: Option<&primus_ntru::split::NativeNtruGadgetGenerator<T>>,
        operation: &crate::CbsParameters<T, LM>,
        rng: &mut R,
    ) -> ProjectionMaterial<T> {
        let parameters = operation.gadget();
        let precision = operation.fourier_precision();
        match operation.projection() {
            crate::NtruProjectionMethod::Separate => ProjectionMaterial::Separate,
            crate::NtruProjectionMethod::FusedLastStage => {
                let crate::FourierPrecision::Split { low_bits } = precision.scheme_switch else {
                    unreachable!("fused configuration requires split SS")
                };
                ProjectionMaterial::LastStage(
                    generator
                        .expect("split generator prepared")
                        .encrypt_scheme_switch_automorphism(
                            parameters.poly_length().get() + 1,
                            parameters.scheme_switch(),
                            low_bits,
                            &mut self.fft,
                            rng,
                        ),
                )
            }
            crate::NtruProjectionMethod::PairedTrace => {
                let TraceMaterial::Split(trace) = trace else {
                    unreachable!("paired configuration requires split trace")
                };
                let crate::FourierPrecision::Split {
                    low_bits: trace_bits,
                } = precision.trace
                else {
                    unreachable!("paired configuration requires split trace")
                };
                let crate::FourierPrecision::Split { low_bits: ss_bits } = precision.scheme_switch
                else {
                    unreachable!("paired configuration requires split SS")
                };
                let generator = generator.expect("split generator prepared");
                let n = parameters.poly_length().get();
                let layers = parameters.poly_length().log_n() as usize;
                let terminal_layers = 2 + (layers & 1);
                let pairs = (0..layers - terminal_layers)
                    .step_by(2)
                    .map(|j| {
                        let alpha = 1 + (1 << (j + 1));
                        let beta = 1 + (1 << (j + 2));
                        let gamma = (alpha * beta) & (2 * n - 1);
                        // Keep the original ATKs for NLEV/dual. Only these transformed
                        // copies and one new product-automorphism key serve paired NGSW.
                        let combined = generator.encrypt_automorphism(
                            gamma,
                            parameters.trace(),
                            trace_bits,
                            &mut self.fft,
                            rng,
                        );
                        [
                            primus_ntru::FourierNtruSplitAutomorphism::new(
                                trace[layers - 1 - j].1.clone(),
                                alpha,
                                self.fft.table(),
                            ),
                            primus_ntru::FourierNtruSplitAutomorphism::new(
                                trace[layers - 2 - j].1.clone(),
                                beta,
                                self.fft.table(),
                            ),
                            primus_ntru::FourierNtruSplitAutomorphism::new(
                                combined,
                                gamma,
                                self.fft.table(),
                            ),
                        ]
                    })
                    .collect();
                let radix = 1 << terminal_layers;
                let terminal = (1..radix)
                    .map(|i| {
                        generator.encrypt_scheme_switch_automorphism(
                            1 + i * 2 * n / radix,
                            parameters.scheme_switch(),
                            ss_bits,
                            &mut self.fft,
                            rng,
                        )
                    })
                    .collect();
                ProjectionMaterial::Paired { pairs, terminal }
            }
            crate::NtruProjectionMethod::FusedLastThreeStages => {
                unreachable!("Fourier context rejects standalone R8 fusion")
            }
        }
    }
}
