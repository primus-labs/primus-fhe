//! Backend-independent message preparation and coefficient-domain LUT compilation.

use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{FactorizedLookupTable, LookupTableCompiler, LookupTableError, PbsMessageConfig};

use crate::PbsParameters;

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Prepares a Rounded compiler for PBS, ManyLUT or odd-domain PBS.
    ///
    /// The rotation program describes the small-q input after any KS/MS; LUT
    /// coefficients use ring Q. Input/output message moduli are independent.
    /// Does not change configured messages or existing clients. With an override,
    /// use [`Self::encryptor_with_message_modulus`] for `messages.input_modulus`
    /// and [`Self::pbs_decryptor_with_message_modulus`] for `messages.output_modulus`.
    /// The external modulus follows the PBS order.
    /// Program geometry and output ranges are checked by the compiler methods.
    pub fn pbs_lookup_table_compiler(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<LookupTableCompiler<T, LM, M>, LookupTableError> {
        let input =
            RoundedCodec::try_new(messages.input_modulus, self.small_lwe().cipher_modulus())
                .map_err(LookupTableError::InputEncoding)?;
        let output = RoundedCodec::try_new(messages.output_modulus, self.ring_modulus())?;
        LookupTableCompiler::try_new(
            self.blind_rotation_params().poly_length(),
            &input,
            self.ring_modulus(),
            &output,
        )
    }

    /// Compiles an MVB coefficient program with Rounded input and Scaled output.
    ///
    /// The input codec uses BR-control q and the fixed integer output scale uses Q.
    /// Backend contexts additionally prepare the factors' NTT/Fourier representation.
    /// `input_domain_len` selects a nonempty prefix of `0..ceil(t_in/2)`;
    /// `output_count` is positive and unpadded, and results must be in `0..t_out`.
    /// Callback order, scale conditions and noise requirements follow
    /// [`FactorizedLookupTable::try_new`].
    ///
    /// Message overrides do not alter configured clients. Bind input through
    /// [`Self::encryptor_with_message_modulus`] and Scaled output through
    /// [`Self::ring_return_decryptor`]. The external decoder's recovery condition
    /// must hold independently of the LUT's Q-domain scale.
    pub fn compile_mvb_fn<F>(
        &self,
        messages: PbsMessageConfig<T>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<FactorizedLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        let input =
            RoundedCodec::try_new(messages.input_modulus, self.small_lwe().cipher_modulus())
                .map_err(LookupTableError::InputEncoding)?;
        let output = ScaledCodec::try_new(messages.output_modulus, self.ring_modulus())?;
        FactorizedLookupTable::try_new(
            input_domain_len,
            self.blind_rotation_params().poly_length(),
            output_count,
            &input,
            &output,
            function,
        )
    }
}
