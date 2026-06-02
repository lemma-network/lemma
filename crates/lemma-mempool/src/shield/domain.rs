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
//!    used only for the commitment expansion side). At combine-time, callers use
//!    [`ShieldDomain::lagrange_coeffs_for`] with the **contributing subset**
//!    (always ≤ all `W`) — this is the production hot path.
//!
//! # Performance: lazy full-set Lagrange cache (§16.1, §16.3)
//!
//! The full-set `λ_k(0)` cache (all `W` points) is computed by
//! `lagrange_basis_at_0_for_all`, which is **O(W²)** — ~4.3 G field-ops for the
//! maximum `W = 65 535`. Production `combine` never needs the full set (it uses
//! [`ShieldDomain::lagrange_coeffs_for`] over the contributing subset), so the
//! full-set cache is computed **lazily on first access** to
//! [`ShieldDomain::lambda_at_full`] via [`OnceLock`]. [`ShieldDomain::new`] is
//! therefore O(W) — instant even for `W = 65 535`. This avoids paying the O(W²)
//! cost in the constructor for a value the settlement path never reads.
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
use std::collections::BTreeSet;
use std::sync::OnceLock;

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

    /// Lazily-computed Lagrange basis values `λ_k(0)` for the **full** set [1..=W].
    ///
    /// Entry `k` = `λ_{k+1}(0)` = the basis polynomial for share ID `k+1`
    /// evaluated at 0, over all `W` x-coordinates. Valid when ALL W shares
    /// contribute. For partial sets (the production combine path), use
    /// [`ShieldDomain::lagrange_coeffs_for`] instead.
    ///
    /// **Lazy** ([`OnceLock`]): computing this is O(W²); it is filled on first
    /// [`ShieldDomain::lambda_at_full`] call, NOT in [`ShieldDomain::new`]
    /// (§16.1 — never pay O(W²) in the constructor for an unread value).
    lambda_full: OnceLock<Vec<Fr>>,

    /// Actual share count W (≤ FFT domain size).
    share_count: u64,
}

impl ShieldDomain {
    /// Construct the fixed FFT domain and share-ID sequence for share count `W`.
    ///
    /// **O(W)** — builds only the FFT domain and the share-ID list. The O(W²)
    /// full-set Lagrange cache is NOT computed here; it is filled lazily on the
    /// first [`ShieldDomain::lambda_at_full`] call (§16.1). This keeps `new`
    /// instant even for the maximum `W = 65 535`.
    ///
    /// # Errors
    ///
    /// - [`ShieldError::DomainTooLarge`] when `w > u16::MAX` (65 535) —
    ///   exceeds the `ShareId = u16` ceiling from `secret_sharing_and_dkg`.
    /// - [`ShieldError::FftDomainFailed`] when the arkworks FFT domain cannot
    ///   be constructed (rounded-up domain exceeds `Fr::TWO_ADICITY = 32`).
    ///   Unreachable for `w ≤ u16::MAX` (max domain = 65 536 = 2¹⁶ << 2³²).
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

        Ok(Self { inner, share_ids, lambda_full: OnceLock::new(), share_count: w })
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

    /// The Lagrange basis value `λ_{share_id}(0)` for the **full** set of all W shares.
    ///
    /// Returns `None` if `share_id` is 0 or > W (out of range).
    /// Index is 1-based (share IDs start at 1).
    ///
    /// **Lazy**: the first call computes the full-set cache (O(W²) via
    /// `lagrange_basis_at_0_for_all`) and stores it in the [`OnceLock`];
    /// subsequent calls are O(1) lookups. Production `combine` uses
    /// [`ShieldDomain::lagrange_coeffs_for`] over the contributing subset and
    /// never triggers this full-set cache.
    ///
    /// Returns `None` (rather than erroring) if the underlying
    /// `lagrange_basis_at_0_for_all` fails — unreachable in Shield's usage
    /// (share IDs are 1..=W, never 0), but handled defensively without panic.
    #[must_use]
    pub fn lambda_at_full(&self, share_id: ShareId) -> Option<Fr> {
        if share_id == 0 || u64::from(share_id) > self.share_count {
            return None;
        }
        // Lazy-init the full-set cache on first access (§16.1: O(W²) deferred
        // out of the constructor). `get_or_init` is thread-safe via OnceLock.
        // On the (unreachable) library-error path, store an empty Vec so the
        // lookup below returns None — never panics (AGENTS §7.2).
        let cache = self.lambda_full.get_or_init(|| {
            lagrange_basis_at_0_for_all::<Fr>(self.share_ids.clone())
                .unwrap_or_default()
        });
        // share_id is 1-based; cache is 0-indexed.
        cache.get(usize::from(share_id) - 1).copied()
    }

    /// Compute Lagrange basis values `λ_k(0)` for a **subset** of share IDs.
    ///
    /// This is the function called at combine-time (S4) with the contributing
    /// validators' share IDs. Results are in the same order as `subset`.
    ///
    /// Subset validation (closed from S1 CodeReviewer W1):
    /// - Rejects share ID `0` (share IDs are 1-indexed; the library errors on 0
    ///   but we guard at our boundary too).
    /// - Rejects share IDs `> W` (out of range for this committee's domain).
    /// - Rejects duplicates (the library returns silently *wrong* Lagrange
    ///   coefficients for duplicate x-coordinates — no panic, just bad math).
    ///
    /// # Errors
    ///
    /// [`ShieldError::Lagrange`] if any of the above conditions hold, or if
    /// `lagrange_basis_at_0_for_all` returns an error.
    pub fn lagrange_coeffs_for(&self, subset: Vec<ShareId>) -> Result<Vec<Fr>, ShieldError> {
        // Validate subset before calling the library (S1 CodeReviewer W1 closed here).
        let mut seen: BTreeSet<ShareId> = BTreeSet::new();
        for &id in &subset {
            if id == 0 {
                return Err(ShieldError::Lagrange(
                    "share ID 0 is invalid (share IDs are 1-indexed)".into(),
                ));
            }
            if u64::from(id) > self.share_count {
                return Err(ShieldError::Lagrange(format!(
                    "share ID {id} out of range (domain size W={})",
                    self.share_count
                )));
            }
            if !seen.insert(id) {
                return Err(ShieldError::Lagrange(format!(
                    "duplicate share ID {id} — would produce invalid Lagrange coefficients"
                )));
            }
        }
        lagrange_basis_at_0_for_all::<Fr>(subset)
            .map_err(|e| ShieldError::Lagrange(format!("{e:?}")))
    }

    /// Reference to the underlying arkworks FFT domain.
    ///
    /// **Not used by S5 PVSS verify.** S5 expands the commitment polynomial via
    /// inline O(W·t) Horner evaluation over the **integer** share IDs (1..=W),
    /// matching the integer Lagrange points used by S4 combine
    /// (`lagrange_basis_at_0_for_all`) — see `pvss::verify` and the module-level
    /// note on integer-vs-roots-of-unity evaluation points. The FFT
    /// roots-of-unity domain is **reserved for the S6 `aggregate` G-FFT
    /// optimization** (O(W log W) batch expansion); it has no S5 consumer.
    #[must_use]
    pub fn fft_domain(&self) -> &Radix2EvaluationDomain<Fr> {
        &self.inner
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
