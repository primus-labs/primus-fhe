use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lwe::LweDimension;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruCiphertext, NtruEncryptionParameters};
use primus_shape::PolyLength;
use primus_tfhe::rotation::RotationModulusSwitch;

use crate::{
    BlindRotationMethod, BlockBootstrappingKeyError, CbsConfig, CbsGadgetConfig, CbsParameters,
    LweCiphertext, PbsConfig, PbsParameters, TfheContextError,
};

/// One boxed owner of the configured operation state, without duplicated samplers.
/// Mixed operations retain their PBS parameters inside the same CBS owner;
/// there is no second BR/domain handle or duplicated sampling state.
enum OperationParameters<T: TorusFftValue, LM: primus_reduce::RingContext<T>> {
    Pbs(Box<PbsParameters<T, LM>>),
    Cbs(Box<CbsParameters<T, LM>>),
}

/// Immutable PBS/CBS parameters and one Fourier transform table.
/// Keys and mutable evaluation workspaces are owned independently.
pub struct TfheContext<T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    parameters: OperationParameters<T, LM>,
    table: Table,
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares and moves one complete BR/KS domain into its transform environment.
    /// No evaluation scratch is allocated.
    pub fn try_from_pbs_config(config: PbsConfig<T, LM>) -> Result<Self, TfheContextError>
    where
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        let parameters = PbsParameters::try_from_config(config)?;
        Self::try_from_parameters(parameters)
    }

    /// Prepares complete CBS state with the required shared KS.
    /// Input and ring secrets remain independent; the common domain is owned once.
    pub fn try_from_cbs_config(config: CbsConfig<T, LM>) -> Result<Self, TfheContextError>
    where
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        let parameters = CbsParameters::try_from_config(config)?;
        Self::try_from_cbs_parameters(parameters)
    }

    /// Moves prepared PBS parameters into a new transform environment.
    /// Borrow them afterward through [`Self::parameters`]; no sampler is cloned.
    /// Rejects an unsupported blind-rotation word size before building the table.
    pub fn try_from_parameters(parameters: PbsParameters<T, LM>) -> Result<Self, TfheContextError> {
        Self::check_blind_rotation_word_size(parameters.blind_rotation_method())?;
        let table = Table::new(parameters.poly_length());
        Ok(Self {
            parameters: OperationParameters::Pbs(Box::new(parameters)),
            table,
        })
    }

    /// Moves complete CBS parameters into a new transform environment.
    /// Direct-input CBS keeps its independent small and ring secret roles.
    /// FusedLastStage and PairedTrace require split trace and SS (their limb widths may differ).
    /// Other fused strategies are rejected before constructing the FFT table.
    pub fn try_from_cbs_parameters(
        parameters: CbsParameters<T, LM>,
    ) -> Result<Self, TfheContextError> {
        let precision = parameters.fourier_precision();
        let supported = match parameters.projection() {
            crate::NtruProjectionMethod::Separate => true,
            crate::NtruProjectionMethod::FusedLastStage
            | crate::NtruProjectionMethod::PairedTrace => {
                matches!(precision.trace, crate::FourierPrecision::Split { .. })
                    && matches!(
                        precision.scheme_switch,
                        crate::FourierPrecision::Split { .. }
                    )
            }
            _ => false,
        };
        if !supported {
            return Err(TfheContextError::UnsupportedProjectionMethod(
                parameters.projection(),
            ));
        }
        let domain = parameters.pbs_parameters();
        Self::check_blind_rotation_word_size(domain.blind_rotation_method())?;
        if precision.blind_rotation != crate::FourierPrecision::Ordinary
            && !domain.external_lwe().secret_key_distr().is_binary()
        {
            return Err(TfheContextError::UnsupportedSplitBlindRotation);
        }
        let table = Table::new(domain.poly_length());
        Ok(Self {
            parameters: OperationParameters::Cbs(Box::new(parameters)),
            table,
        })
    }

    /// Binds a prepared PBS domain to an independently supplied transform table.
    /// Checks the table pairing and supported word size without cloning samplers.
    pub fn try_new(
        parameters: PbsParameters<T, LM>,
        table: Table,
    ) -> Result<Self, TfheContextError> {
        Self::check_blind_rotation_word_size(parameters.blind_rotation_method())?;
        let expected = parameters.poly_length().get();
        let actual = table.poly_length().get();
        if expected != actual {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        Ok(Self {
            parameters: OperationParameters::Pbs(Box::new(parameters)),
            table,
        })
    }

    fn check_blind_rotation_word_size(method: BlindRotationMethod) -> Result<(), TfheContextError> {
        if method == BlindRotationMethod::Block && T::BITS != 64 {
            return Err(
                BlockBootstrappingKeyError::UnsupportedFourierWordSize { bits: T::BITS }.into(),
            );
        }
        Ok(())
    }

    /// Adds CBS by moving the same PBS domain into the combined operation owner.
    /// Selects Separate projection. Only new gadgets and selector encoding are
    /// prepared; the table is retained.
    pub fn try_with_circuit_bootstrap(
        self,
        gadget: CbsGadgetConfig,
    ) -> Result<Self, TfheContextError> {
        let parameters = match self.parameters {
            OperationParameters::Pbs(parameters) => *parameters,
            OperationParameters::Cbs(parameters) => parameters.into_pbs_parameters(),
        };
        let parameters = CbsParameters::try_with_config(
            parameters,
            gadget,
            crate::NtruProjectionMethod::Separate,
        )?;
        Ok(Self {
            parameters: OperationParameters::Cbs(Box::new(parameters)),
            table: self.table,
        })
    }

    /// Representation required by this context's shared BR material.
    pub(crate) fn br_precision(&self) -> crate::FourierPrecision {
        self.cbs_parameters()
            .map_or(crate::FourierPrecision::Ordinary, |p| {
                p.fourier_precision().blind_rotation
            })
    }

    /// Borrows complete CBS state, which contains the single common domain.
    #[must_use]
    pub fn cbs_parameters(&self) -> Option<&CbsParameters<T, LM>> {
        match &self.parameters {
            OperationParameters::Cbs(parameters) => Some(parameters),
            OperationParameters::Pbs(_) => None,
        }
    }

    /// Borrows the common checked domain used by numerical kernels and clients.
    #[must_use]
    #[inline(always)]
    pub fn parameters(&self) -> &PbsParameters<T, LM> {
        match &self.parameters {
            OperationParameters::Pbs(parameters) => parameters,
            OperationParameters::Cbs(parameters) => parameters.pbs_parameters(),
        }
    }

    /// Borrows the immutable transform table; transformed keys use this representation.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Creates independent reusable FFT scratch, borrowing the immutable table.
    #[must_use]
    pub fn new_fft_engine(&self) -> FftEngine<'_, Table> {
        FftEngine::new(&self.table)
    }

    /// Allocates zero storage for an external LWE; this does not encrypt a message.
    #[must_use]
    pub fn allocate_lwe_ciphertext(&self) -> LweCiphertext<T> {
        LweCiphertext::zero(self.parameters().external_lwe_dimension().get())
    }

    /// Allocates zero storage in the accumulator layout, without encrypting.
    #[must_use]
    pub fn allocate_accumulator_ciphertext(&self) -> NtruCiphertext<Vec<T>> {
        NtruCiphertext::zero(self.parameters().poly_length().get())
    }
}

/// Server-only borrowing of the existing ring/input domain and transform table.
/// No external-LWE sampler or reducer is retained. Parameter/table addresses preserve
/// context identity even when two contexts have numerically equal parameters.
pub(crate) struct EvaluationContext<'a, T: TorusFftValue, Table: FftTable> {
    blind_rotation: &'a NlevParameters<T, NativeModulus<T>>,
    input_dimension: LweDimension,
    input_modulus: Option<T>,
    rotation_modulus_switch: &'a RotationModulusSwitch<T>,
    table: &'a Table,
}

impl<T: TorusFftValue, Table: FftTable> Copy for EvaluationContext<'_, T, Table> {}
impl<T: TorusFftValue, Table: FftTable> Clone for EvaluationContext<'_, T, Table> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, T: TorusFftValue, Table: FftTable> EvaluationContext<'a, T, Table> {
    #[must_use]
    pub(crate) fn blind_rotation(self) -> &'a NlevParameters<T, NativeModulus<T>> {
        self.blind_rotation
    }

    #[must_use]
    pub(crate) fn poly_length(self) -> PolyLength {
        self.blind_rotation.poly_length()
    }

    #[must_use]
    pub(crate) fn accumulator_ntru(self) -> &'a NtruEncryptionParameters<T, NativeModulus<T>> {
        self.blind_rotation.encryption_parameters()
    }

    #[must_use]
    pub(crate) fn external_lwe_dimension(self) -> LweDimension {
        self.input_dimension
    }

    #[must_use]
    pub(crate) fn input_modulus_value(self) -> Option<T> {
        self.input_modulus
    }

    #[must_use]
    pub(crate) fn rotation_modulus_switch(self) -> RotationModulusSwitch<T> {
        *self.rotation_modulus_switch
    }

    #[must_use]
    pub(crate) fn is_same(self, other: Self) -> bool {
        core::ptr::eq(self.blind_rotation, other.blind_rotation)
            && core::ptr::eq(self.rotation_modulus_switch, other.rotation_modulus_switch)
            && core::ptr::eq(self.table, other.table)
    }
}

impl<T: TorusFftValue, Table: FftTable, LM: primus_reduce::RingContext<T>>
    TfheContext<T, Table, LM>
{
    #[must_use]
    pub(crate) fn evaluation_context(&self) -> EvaluationContext<'_, T, Table> {
        let parameters = self.parameters();
        EvaluationContext {
            blind_rotation: parameters.blind_rotation(),
            input_dimension: parameters.external_lwe_dimension(),
            input_modulus: parameters.external_lwe().cipher_modulus_value(),
            rotation_modulus_switch: parameters.rotation_modulus_switch(),
            table: self.table(),
        }
    }
}
