//! Same-secret conversion from coefficient NLev to transformed NGSW.

#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "ntt")]
pub use ntt::NttNtruSchemeSwitchKey;

#[cfg(feature = "ntt")]
mod projection;
#[cfg(feature = "ntt")]
pub use projection::NttNtruProjectionKey;

/// Algorithm for projecting packed coefficients to same-secret NGSW rows.
///
/// Applies only to NGSW-only CBS/one-hot output. NLEV-only and dual-output
/// operations retain separate trace and, for dual output, separate scheme switching.
/// [`Self::Separate`] is the enum default; NTT performance presets explicitly
/// select [`Self::PairedTrace`]. Choose before generating keys and workspaces.
///
/// These choices describe arithmetic schedules. Fused strategies change decomposition
/// residuals and correlated key errors; changing strategy requires a new noise budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NtruProjectionMethod {
    /// Complete normalized reverse trace, followed by separate scheme switching.
    #[default]
    Separate,
    /// Separate reverse-trace prefix; fuse its last layer with scheme switching.
    FusedLastStage,
    /// Separate reverse-trace prefix; fuse its last three layers with scheme switching.
    FusedLastThreeStages,
    /// Pair consecutive reverse-trace layers, then fuse the final two layers
    /// with scheme switching for even log2(N), or the final three for odd log2(N).
    PairedTrace,
}
