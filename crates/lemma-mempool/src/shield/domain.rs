//! `ShieldDomain` — fixed radix-2 FFT evaluation domain + Lagrange cache.
//!
//! The **determinism anchor** for the entire Shield subsystem (15-SHIELD_SPEC §7.1):
//! every node seeding the same `W` produces the **identical** FFT domain,
//! the identical share-ID sequence, and the identical Lagrange coefficients.
//!
//! # Two uses of the domain
//!
//! 1. **Commitment expansion (PVSS verify, S5)**: `Radix2EvaluationDomain::<Fr>`
//!    lets us expand `t+1` polynomial coefficient-commitments into `W` evaluation
//!    points efficiently via FFT (§4.3 step 2). The FFT domain size = next
//!    power-of-two ≥ `W` (arkworks `EvaluationDomain::new` rounds up silently).
//!
//! 2. **Lagrange interpolation (combine, S4)**: share IDs `[1, 2, …, W]` are
//!    the x-coordinates for `lagrange_basis_at_0_for_all` (docknetwork). These
//!    are **integers** cast to `𝔽_r` — NOT the FFT roots of unity (which are
//!    used only for the commitment expansion side). The full-set cache stores
//!    `λ_k(0)` for the entire domain; at combine-time, callers use
//!    [`ShieldDomain::lagrange_coeffs_for`] with the contributing subset.
//!
//! # Determinism rules (§7.1, §7.5)
//!
//! - Domain is seeded **only** from canonical `W` — no per-node randomness.
//! - Share IDs are fixed: `[1, 2, …, W]` (1-indexed; 0 is forbidden by
//!   `lagrange_basis_at_0_for_all`).
//! - `lagrange_basis_at_0_for_all` is deterministic for the same x-coordinates.
//! - Two nodes with identical `W` derive byte-identical `lambda_full`.

use ark_bls12_381::Fr;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use secret_sharing_and_dkg::common::{lagrange_basis_at_0_for_all, ShareId};

use crate::shield::ShieldError;

// ── ShieldDomain ──────────────────────────────────────────────────────────────

/// Fixed FFT evaluation domain and Lagrange cache for one Shield committee size.
///
/// Constructed once per epoch from the committee's total share count `W`.
/// Immutable after construction — both the FFT domain and the Lagrange cache
/// are deterministically fixed for that `W`.
///
/// # Note on domain size vs share count
///
/// The arkworks `Radix2EvaluationDomain` rounds `W` up to the next power of
/// two. [`ShieldDomain::fft_size`] returns this rounded size (used for FFT
/// commitment expansion), while [`ShieldDomain::share_count`] returns the
/// actual `W` (used for Lagrange interpolation and the share-ID sequence).
#[derive(Clone, Debug)]
pub struct ShieldDomain {
    /// Radix-2 FFT evaluation domain (size = next power-of-two ≥ W).
    /// Used for polynomial commitment expansion in PVSS verify (§4.3 step 2).
    inner: Radix2EvaluationDomain<Fr>,

    /// Canonical share IDs: `[1, 2, …, W]` as `u16`.
    ///
    /// These are the x-coordinates for Lagrange interpolation (docknetwork
    /// `lagrange_basis_at_0_for_all` treats them as `𝔽_r::from(share_id)`).
    /// 1-indexed because `lagrange_basis_at_0_for_all` errors on x = 0.
    share_ids: Vec<ShareId>,

    /// Precomputed Lagrange basis values `λ_k(0)` for the **full** set [1..=W].
    ///
    /// Entry `k` = `λ_{k+1}(0)` = the basis polynomial for share ID `k+1`
    /// evaluated at 0, over all `W` x-coordinates. Valid when ALL W shares
    /// contribute. For partial sets (typical in combine), use
    /// [`ShieldDomain::lagrange_coeffs_for`].
    lambda_full: Vec<Fr>,

    /// Actual share count W (≤ FFT domain size).
    share_count: u64,
}

impl ShieldDomain {
    /// Construct the fixed FFT domain and Lagrange cache for share count `W`.
    ///
    /// # Errors
    ///
    /// - [`ShieldError::DomainTooLarge`] when `w > u16::MAX` (65 535) —
    ///   exceeds the `ShareId = u16` ceiling from `secret_sharing_and_dkg`.
    /// - [`ShieldError::FftDomainFailed`] when the arkworks FFT domain cannot
    ///   be constructed (rounded-up domain exceeds `Fr::TWO_ADICITY = 32`).
    ///   Unreachable for `w ≤ u16::MAX` (max domain = 65 536 = 2¹⁶ << 2³²).
    /// - [`ShieldError::Lagrange`] when `lagrange_basis_at_0_for_all` returns
    ///   an error. Unreachable in Shield's usage (ShareIds are 1..=W, never 0).
    pub fn new(w: u64) -> Result<Self, ShieldError> {
        // Guard: ShareId = u16 caps the maximum useful W.
        if w > u64::from(u16::MAX) {
            return Err(ShieldError::DomainTooLarge { size: w });
        }

        // Build the radix-2 FFT domain. `new(n)` rounds up to next power of 2
        // (EvaluationDomain::new API, verified 2026-06-02 via ExternalScout).
        // Safe cast: w ≤ 65_535 ≤ usize::MAX on all supported platforms.
        let inner = Radix2EvaluationDomain::<Fr>::new(w as usize)
            .ok_or(ShieldError::FftDomainFailed { size: w })?;

        // Build the canonical share-ID sequence [1, 2, …, W].
        // Safe cast: w ≤ u16::MAX checked above.
        let share_ids: Vec<ShareId> = (1u16..=w as u16).collect();

        // Precompute full-set Lagrange coefficients.
        // `lagrange_basis_at_0_for_all` takes owned Vec<u16>, so we clone.
        // Semantics: λ_k(0) = ∏_{j≠k} (0 − x_j) / (x_k − x_j), x_i = F::from(i).
        let lambda_full: Vec<Fr> =
            lagrange_basis_at_0_for_all::<Fr>(share_ids.clone())
                .map_err(|e| ShieldError::Lagrange(format!("{e:?}")))?;

        debug_assert_eq!(
            lambda_full.len(),
            w as usize,
            "Lagrange cache length must equal W"
        );

        Ok(Self { inner, share_ids, lambda_full, share_count: w })
    }

    /// Total share count `W` (the logical domain size).
    ///
    /// This is the number of share IDs [1..=W] and the length of the
    /// Lagrange cache. The FFT domain size may be larger (next power of 2).
    #[must_use]
    pub fn share_count(&self) -> u64 {
        self.share_count
    }

    /// Actual FFT evaluation domain size (next power-of-two ≥ W).
    ///
    /// Used for polynomial commitment expansion in PVSS (§4.3 step 2).
    #[must_use]
    pub fn fft_size(&self) -> usize {
        self.inner.size()
    }

    /// The canonical share-ID sequence `[1, 2, …, W]`.
    #[must_use]
    pub fn share_ids(&self) -> &[ShareId] {
        &self.share_ids
    }

    /// The precomputed Lagrange basis value `λ_{share_id}(0)` for the **full**
    /// set of all W shares.
    ///
    /// Returns `None` if `share_id` is 0 or > W (out of range).
    /// Index is 1-based (share IDs start at 1).
    #[must_use]
    pub fn lambda_at_full(&self, share_id: ShareId) -> Option<Fr> {
        if share_id == 0 || u64::from(share_id) > self.share_count {
            return None;
        }
        // share_id is 1-based; lambda_full is 0-indexed.
        self.lambda_full.get(usize::from(share_id) - 1).copied()
    }

    /// Compute Lagrange basis values `λ_k(0)` for a **subset** of share IDs.
    ///
    /// This is the function called at combine-time (S4) with the contributing
    /// validators' share IDs. Results are in the same order as `subset`.
    ///
    /// # Errors
    ///
    /// [`ShieldError::Lagrange`] if `lagrange_basis_at_0_for_all` errors
    /// (only occurs if `subset` contains a 0 — which Shield never produces).
    ///
    /// # TODO(shield): subset validation — CodeReviewer W1
    ///
    /// At S4 (combine), add validation before calling the library:
    ///
    /// - Reject ShareId 0 (library errors, but guard at our boundary too)
    /// - Reject IDs > W (out of range)
    /// - Reject duplicates (library returns wrong coefficients silently — no
    ///   panic, but the result is mathematically invalid)
    ///
    /// Validation: build a `BTreeSet<ShareId>`, check no dups, check range.
    pub fn lagrange_coeffs_for(&self, subset: Vec<ShareId>) -> Result<Vec<Fr>, ShieldError> {
        // TODO(shield): add subset validation here when S4 (combine) is built — see W1 above.
        lagrange_basis_at_0_for_all::<Fr>(subset)
            .map_err(|e| ShieldError::Lagrange(format!("{e:?}")))
    }

    /// Reference to the underlying arkworks FFT domain.
    ///
    /// Used by PVSS verify (S5) for polynomial commitment expansion (§4.3 step 2):
    /// `domain.fft_domain().fft(coefficients)` → evaluation at all domain points.
    #[must_use]
    pub fn fft_domain(&self) -> &Radix2EvaluationDomain<Fr> {
        &self.inner
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
