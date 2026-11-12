//! Packed one-hot selectors from one fused blind rotation.

use primus_data::{Data, DataMut};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lattice::{ngsw::NttNgswIterMut, nlev::NlevIterMut};
use primus_ntru::{NlevCiphertext, NtruCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;

use crate::{
    Lwe, TfheContext,
    bootstrap::BootstrapResources,
    circuit_bootstrap::{CbsGadgetParameters, CircuitBootstrapKey},
    context::EvaluationContext,
};
pub use primus_tfhe_ntru::{NlevSelectors, OneHotBootstrapError, OneHotLookupTable};

mod pair;
pub use pair::OneHotProjection;

mod selectors;
pub use selectors::NttNgswSelectors;

/// One-hot extension of CBS for Classic and Block BR.
///
/// Input uses unsigned Rounded encoding with t=2*M, M=2^tau, tau>=1.
/// Full-output methods materialize all M selectors, including r=0;
/// [`Self::one_hot_nonzero_ngsw_to`] omits r=0 before projection and scheme switching.
/// NLEV outputs are coefficient polynomials under accumulator secret f at Q;
/// NGSW outputs use this backend's transform representation. Layout is `[selector][level][polynomial element]`,
/// in natural selector order and output-basis scalar order, with no padding.
/// Each selector-generation call performs one BR and L full constant projections per selector.
/// Online calls overwrite outputs, reuse BR external-product scratch, and allocate nothing.
/// Owns only the packed LUT and projection buffers; common BR/EP resources are
/// borrowed per operation and no return buffers are owned.
/// Ordinary CBS remains available through [`crate::circuit_bootstrap::CircuitBootstrapEvaluator`].
/// The input reducer is needed only at construction; selector generation
/// retains the domain binding and uses ring arithmetic.
/// NGSW-only calls use the projection strategy bound to the circuit key.
/// NLEV outputs always retain ordinary full trace; dual outputs additionally use
/// ordinary SS. Both paths encrypt the same selectors, but their NGSW ciphertexts/noise
/// need not coincide. See
/// [`primus_ntru::NttNtruProjectionKey`] for the fused noise and key contract.
pub struct OneHotCircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: EvaluationContext<'a, T, Table>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: OneHotLookupTable<T>,
    projection_scratch: Vec<T>,
    projected: NlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> OneHotCircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Compiles the packed LUT and allocates projection buffers for this context.
    /// Common BR resources are supplied only for online calls and must come from
    /// the same context. A CBS-enabled context must match the key's configured
    /// projection and gadgets; a PBS-only context uses the supplied key's strategy.
    ///
    /// # Correctness
    /// The circuit key must share the context's intended accumulator secret and
    /// NTT representation; compatibility checks do not establish these identities.
    /// Switching between classic and grouped resources must preserve both secrets.
    pub fn try_new<LM: primus_reduce::RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<Self, OneHotBootstrapError> {
        // PBS-only contexts use the supplied key's strategy; CBS contexts must agree.
        if context
            .cbs_parameters()
            .is_some_and(|parameters| !circuit_key.is_compatible(parameters))
        {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapKey.into());
        }
        // The packed LUT constructor checks the key's CBS domain against these
        // TFHE parameters, as well as input encoding and selector geometry.
        let lookup_table = OneHotLookupTable::try_new(
            context.parameters(),
            circuit_key.parameters(),
            input_codec,
        )?;
        let projected = NlevCiphertext::zero(circuit_key.parameters().output_nlev_len());
        Ok(Self {
            context: context.evaluation_context(),
            circuit_key,
            lookup_table,
            projection_scratch: vec![T::ZERO; circuit_key.projection.scratch_len()],
            projected,
        })
    }

    /// Returns the packed LUT geometry, including selector count, stride and guard radius.
    #[must_use]
    pub fn lookup_table(&self) -> &OneHotLookupTable<T> {
        &self.lookup_table
    }

    /// Returns the shared CBS bases and accumulator layouts.
    #[must_use]
    pub fn parameters(&self) -> &'a CbsGadgetParameters<T> {
        self.circuit_key.parameters()
    }

    /// Returns the storage length of one transformed NGSW selector: L*N NTT ring elements.
    /// This is an element count, not a byte count or the length of the whole batch.
    #[must_use]
    pub fn ngsw_selector_len(&self) -> usize {
        self.parameters().output_nlev_len()
    }

    /// Returns the complete transformed NGSW batch length: M*L*N NTT ring elements.
    /// Includes every branch r=0..M-1 in selector-major order. The nonzero-only
    /// batch omits exactly one [`Self::ngsw_selector_len`] block.
    #[must_use]
    pub fn ngsw_batch_len(&self) -> usize {
        self.lookup_table.output_nlev_len()
    }

    /// Borrows the complete coefficient-domain NLEV batch, indexed by branch r.
    /// Inherits [`OneHotLookupTable::nlev_selectors`]'s shape and identity requirements.
    #[must_use]
    pub fn nlev_selectors<'b>(&self, output: &'b [T]) -> NlevSelectors<'b, T> {
        self.lookup_table.nlev_selectors(output)
    }

    /// Borrows the full transformed NGSW batch with branches r=0..M-1.
    /// Storage must come from compatible one-hot output; this view checks shape,
    /// not the output basis, accumulator secret or transform identity.
    ///
    /// # Panics
    /// Panics unless the buffer contains exactly M complete NGSW selectors.
    #[must_use]
    pub fn ngsw_selectors<'b>(&self, output: &'b [T]) -> NttNgswSelectors<'b, T> {
        NttNgswSelectors::new(
            output,
            0,
            self.lookup_table.selector_count(),
            self.ngsw_selector_len(),
        )
    }

    /// Borrows the compact NGSW batch with branches r=1..M-1.
    /// `selector(1)` accesses its first stored control; `selector(0)` returns
    /// `None`. Inherits [`Self::ngsw_selectors`]'s representation requirements.
    ///
    /// # Panics
    /// Panics unless the buffer contains exactly M-1 complete NGSW selectors.
    #[must_use]
    pub fn nonzero_ngsw_selectors<'b>(&self, output: &'b [T]) -> NttNgswSelectors<'b, T> {
        NttNgswSelectors::new(
            output,
            1,
            self.lookup_table.selector_count() - 1,
            self.ngsw_selector_len(),
        )
    }

    /// Allocates M*L*N coefficients for all NLEV selectors. Reuse with [`Self::one_hot_nlev_to`].
    #[must_use]
    pub fn allocate_nlev_output(&self) -> Vec<T> {
        vec![T::ZERO; self.lookup_table.output_nlev_len()]
    }

    /// Allocates all transformed NGSW selectors: M*L*N elements.
    #[must_use]
    pub fn allocate_ngsw_output(&self) -> Vec<T> {
        vec![T::ZERO; self.ngsw_batch_len()]
    }

    /// Allocates (M-1)*L*N elements for selectors r=1..M-1.
    /// Reuse with [`Self::one_hot_nonzero_ngsw_to`].
    #[must_use]
    pub fn allocate_nonzero_ngsw_output(&self) -> Vec<T> {
        vec![T::ZERO; self.ngsw_batch_len() - self.ngsw_selector_len()]
    }

    /// Writes coefficient NLEV selectors only, without scheme switching.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_nlev_to(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut [T],
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        self.evaluate(input, 0, Some(output), None, resources);
    }

    /// Writes transformed NGSW selectors only; retains no full NLEV output batch.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut [T],
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        self.evaluate(input, 0, None, Some(output), resources);
    }

    /// Writes only the transformed NGSW selectors for branches r=1..M-1.
    /// Output is packed as `[r-1][level][row element]`, with exactly (M-1)*L*N elements.
    /// For input m=0, all output target bits are zero. No r=0 projection or scheme
    /// switch is performed; the shared blind rotation and input guard are unchanged.
    /// Output is fully overwritten without allocation or prior clearing.
    ///
    /// # Correctness
    /// Inherits [`Self::one_hot_to`]'s input, representation and noise requirements.
    ///
    /// # Panics
    /// Rejects a different context binding, input dimension or exact output
    /// length before BR or output writes.
    pub fn one_hot_nonzero_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut [T],
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        self.evaluate(input, 1, None, Some(output), resources);
    }

    /// Writes both selector representations from the same BR and coefficient projections.
    /// NLEV row length is N; NGSW row length is N.
    /// NLEV phases target g_l*delta_r(m); NGSW phases target g_l*f*delta_r(m).
    ///
    /// # Correctness
    /// Input uses the bound external LWE secret and modulus q, with
    /// `m in 0..M` and phase `round(q*m/(2*M))+noise`. For the actual per-coordinate
    /// quantized phase, require `u_bar=S*m+W*e mod 2N` with integer `-A<=e<A`;
    /// see [`OneHotLookupTable`]. This includes encoding and quantization error,
    /// not just encryption noise. Coefficients must be canonical in their domains.
    /// The BR basis must resolve the smallest output gadget scale. Budget trace,
    /// decomposition and scheme-switch f/f² amplification separately. NTT trace
    /// uses modular inverse halving. Geometry checks are not noise or security
    /// certification. See [`CbsGadgetParameters`].
    ///
    /// # Panics
    /// Rejects a different context binding, input dimension or exact output
    /// lengths before BR or output writes.
    /// Output buffers contain no padding and need no prior reset.
    pub fn one_hot_to(
        &mut self,
        input: Lwe<&[T]>,
        nlev_output: &mut [T],
        ngsw_output: &mut [T],
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        self.evaluate(input, 0, Some(nlev_output), Some(ngsw_output), resources);
    }

    /// Writes all M coefficient NLEVs and only the r=1..M-1 transformed NGSWs.
    /// Shares one blind rotation and each coefficient projection; branch zero
    /// is projected for NLEV but never scheme-switched. Buffer layouts and
    /// correctness requirements are those of [`Self::one_hot_nlev_to`] and
    /// [`Self::one_hot_nonzero_ngsw_to`].
    ///
    /// # Panics
    /// Inherits the resource-binding, input-dimension and output-length checks
    /// of [`Self::one_hot_to`] and [`Self::one_hot_nonzero_ngsw_to`].
    pub fn one_hot_nlev_and_nonzero_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        nlev_output: &mut [T],
        ngsw_output: &mut [T],
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        self.evaluate(input, 1, Some(nlev_output), Some(ngsw_output), resources);
    }

    /// NLEV, when requested, always contains every branch. NGSW may omit zero;
    /// its compact slot is r-first_ngsw_selector. Project each needed branch
    /// once and retain no extra full NLEV batch for NGSW-only calls.
    fn evaluate(
        &mut self,
        input: Lwe<&[T]>,
        first_ngsw_selector: usize,
        nlev_output: Option<&mut [T]>,
        ngsw_output: Option<&mut [T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        resources.check_context(self.context);
        assert_eq!(
            input.dimension(),
            resources.context.external_lwe_dimension().get(),
            "one-hot input dimension mismatch"
        );
        self.check_output_lengths(
            first_ngsw_selector,
            nlev_output.as_deref(),
            ngsw_output.as_deref(),
        );

        resources.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.rotation_step(),
        );

        self.project(first_ngsw_selector, nlev_output, ngsw_output, resources);
    }

    // Check complete batches before semantic iterators can discard an incomplete tail.
    fn check_output_lengths(
        &self,
        first_ngsw_selector: usize,
        nlev: Option<&[T]>,
        ngsw: Option<&[T]>,
    ) {
        if let Some(output) = nlev {
            assert_eq!(
                output.len(),
                self.lookup_table.output_nlev_len(),
                "one-hot NLEV output length mismatch"
            );
        }
        if let Some(output) = ngsw {
            assert_eq!(
                output.len(),
                (self.lookup_table.selector_count() - first_ngsw_selector)
                    * self.ngsw_selector_len(),
                "one-hot NGSW output length mismatch"
            );
        }
    }

    /// Project an already prepared BR result, retaining the shared scratch contract.
    // Preserve specialization for single-input callers after splitting BR and projection.
    #[inline]
    fn project(
        &mut self,
        first_ngsw_selector: usize,
        nlev_output: Option<&mut [T]>,
        ngsw_output: Option<&mut [T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        let tfhe = resources.context;
        let selector_len = self.ngsw_selector_len();
        let selector_count = self.lookup_table.selector_count();
        // Without NLEV, omit branch zero before projection as well as conversion.
        let first_selector = if nlev_output.is_some() {
            0
        } else {
            first_ngsw_selector
        };
        let mut nlevs = nlev_output.map(|output| NlevIterMut::new(output, selector_len));
        let mut ngsws = ngsw_output.map(|output| NttNgswIterMut::new(output, selector_len));
        for selector in first_selector..selector_count {
            // Negative BR places selector r at -r*S+l, including its negacyclic
            // sign. Rotate by +r*S first; prefix projection then shifts by -l.
            // General BR tails are nonzero: prefix expansion is not valid here.
            resources.blind_rotation.current.mul_monomial_to(
                selector * self.lookup_table.selector_stride(),
                &mut resources.blind_rotation.scratch,
                tfhe.accumulator_ntru().cipher_modulus(),
            );
            // Full NLEV batches start at zero; compact NGSW batches start at one.
            // Advance each semantic iterator only when this branch belongs to it.
            let ngsw = if selector >= first_ngsw_selector {
                ngsws.as_mut().and_then(Iterator::next)
            } else {
                None
            };
            if let Some(mut nlev) = nlevs.as_mut().and_then(Iterator::next) {
                // NLEV/dual outputs deliberately use ordinary full trace, independent
                // of the NGSW-only strategy. Its 2N scratch reuses the same allocation.
                self.circuit_key
                    .trace_key()
                    .project_prefix_coefficients_with_scratch_to(
                        &resources.blind_rotation.scratch,
                        self.lookup_table.level_count().get(),
                        nlev.as_mut(),
                        tfhe.accumulator_ntru().cipher_modulus(),
                        resources.context.table(),
                        &mut self.projection_scratch[..2 * tfhe.poly_length().get()],
                        resources.blind_rotation.rotation.external_product(),
                    );
                if let Some(mut ngsw) = ngsw {
                    self.circuit_key.scheme_switch_key().apply_to(
                        &nlev,
                        &mut ngsw,
                        tfhe.accumulator_ntru().cipher_modulus(),
                        resources.context.table(),
                        resources.blind_rotation.rotation.external_product(),
                    );
                }
            } else if let Some(ngsw) = ngsw {
                // Ordinary CBS and NGSW-only selectors share this four-strategy entry.
                self.circuit_key.projection.project_to(
                    resources.blind_rotation.scratch.as_view(),
                    ngsw,
                    self.projected.as_mut(),
                    &mut self.projection_scratch,
                    tfhe.accumulator_ntru().cipher_modulus(),
                    resources.context.table(),
                    resources.blind_rotation.rotation.external_product(),
                );
            }
        }
    }
}

// Consume a borrowed selector with the same CBS binding as ordinary controls.
impl<'a, T, Table> OneHotCircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Selects `lhs` when delta_r is zero and `rhs` when delta_r is one.
    /// Accepts one NGSW borrowed from a full or nonzero selector batch and
    /// overwrites the coefficient-domain output using shared scratch, without allocating.
    ///
    /// # Correctness
    /// `control` must use this evaluator's output basis, accumulator secret and
    /// transform representation. Inherits the candidate encoding, residue and
    /// noise requirements of [`crate::circuit_bootstrap::CircuitBootstrapEvaluator::cmux_to`].
    ///
    /// # Panics
    /// Panics before output writes on a different context binding or a wrong
    /// single-control/candidate/output length. Pass one selector, not a whole batch.
    pub fn cmux_to<A, B, C, D>(
        &self,
        control: &NttNgswCiphertext<A>,
        lhs: &NtruCiphertext<B>,
        rhs: &NtruCiphertext<C>,
        output: &mut NtruCiphertext<D>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        super::control::cmux_to(
            self.parameters(),
            control.as_view(),
            lhs.as_view(),
            rhs.as_view(),
            output.as_mut_view(),
            resources,
        );
    }

    /// Multiplies an accumulator ciphertext by one NGSW selector delta_r.
    /// Overwrites output using shared scratch, without allocating.
    ///
    /// # Correctness
    /// Inherits [`Self::cmux_to`]'s basis, secret and representation requirements
    /// and [`crate::circuit_bootstrap::CircuitBootstrapEvaluator::external_product_to`]'s encoding,
    /// residue and multiplication-noise requirements.
    ///
    /// # Panics
    /// Panics before output writes on a different context binding or a wrong
    /// single-control/input/output length.
    pub fn external_product_to<A, B, C>(
        &self,
        control: &NttNgswCiphertext<A>,
        input: &NtruCiphertext<B>,
        output: &mut NtruCiphertext<C>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        super::control::external_product_to(
            self.parameters(),
            control.as_view(),
            input.as_view(),
            output.as_mut_view(),
            resources,
        );
    }
}
