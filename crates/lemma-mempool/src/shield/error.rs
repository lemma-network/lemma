//! `ShieldError` — all error variants for the Shield subsystem.
//!
//! Single home for every `ShieldError` variant, grown per sub-step (S1–S8).
//! All variants carry enough context to diagnose failures (AGENTS.md §12.2).
//!
//! **Settlement-path invariant**: every Shield function in the post-order
//! settlement path returns `Result<_, ShieldError>` — it **never panics**
//! (15-SHIELD_SPEC §6, AGENTS.md §7.2, Sui-stall lesson).

use lemma_core::Address;

/// All errors produced by the Shield subsystem (15-SHIELD_SPEC §8.2).
///
/// `#[non_exhaustive]` allows adding variants in future sub-steps (S2–S8)
/// without breaking downstream `match` arms (AGENTS.md §4.3).
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum ShieldError {
    // ── S1: foundation — params / committee / domain ──────────────────────────

    /// Committee total weight `W` is too small for viable threshold parameters.
    ///
    /// Minimum viable `W = 4` yields `t = 0` (secrecy threshold) and `p = 2`
    /// (privacy threshold; decryption needs ≥ 3 of 4 shares). Smaller values
    /// produce degenerate thresholds (t underflows below 0 for W < 3; W = 3
    /// gives t = 0 with no corruption tolerance for secrecy).
    ///
    /// In practice the genesis minimum stake (20M LEM) and 1M-LEM-per-share
    /// granularity give each validator ≥ 20 shares, so this error only fires
    /// on an empty or near-empty committee.
    #[error("committee weight W={have} is too small (minimum W=4 for viable thresholds)")]
    CommitteeTooSmall { have: u64 },

    /// A committee member's stake rounds down to zero shares under the current
    /// weight granularity and cannot be assigned a share in the Ω_i partition.
    ///
    /// Validators with active stake below `WEIGHT_GRANULARITY_DROP`
    /// (1 000 000 LEM, currently) receive zero shares and are rejected.
    /// The `ValidatorSet` passed to `ShieldCommittee::from_validator_set`
    /// should only contain bonded validators with sufficient stake.
    #[error("validator {0} has zero share weight — stake below weight granularity threshold")]
    ZeroWeightValidator(Address),

    /// Total share count `W` exceeds the maximum `ShareId` range.
    ///
    /// `ShareId` (from `secret_sharing_and_dkg`) is `u16`, capping `W` at
    /// 65 535. With 1M-LEM-per-share granularity and a 1B-LEM total supply,
    /// `W ≤ 1 000` in practice — this error is unreachable under normal
    /// operating conditions and guards against misconfiguration.
    #[error("domain size W={size} exceeds maximum ShareId range (u16::MAX = 65535)")]
    DomainTooLarge { size: u64 },

    /// The fixed radix-2 FFT evaluation domain could not be constructed.
    ///
    /// Fires when `Radix2EvaluationDomain::<Fr>::new(w)` returns `None`,
    /// which occurs when the rounded-up power-of-two size exceeds the scalar
    /// field's two-adicity (`Fr::TWO_ADICITY` for BLS12-381 = 32). With
    /// `W ≤ u16::MAX = 65 535`, the required domain size is at most 65 536 =
    /// 2^16, which is well within BLS12-381's two-adicity. Guards against
    /// future misuse with a different field or extreme W values.
    #[error("FFT evaluation domain construction failed for W={size} (exceeds field two-adicity?)")]
    FftDomainFailed { size: u64 },

    /// Lagrange basis computation returned an error from `secret_sharing_and_dkg`.
    ///
    /// In Shield's usage (ShareIds = 1..=W, never 0), this error is
    /// unreachable — the docknetwork library errors only when an x-coordinate
    /// is 0. Included for defensive error handling.
    #[error("Lagrange basis computation failed: {0}")]
    Lagrange(String),

    // ── S2: ciphertext + TPKE encrypt/validate ────────────────────────────────

    /// A submitted or deserialized ciphertext failed the pairing validity check.
    ///
    /// Either `e(U, H_𝔾₂(U,aad)) ≠ e(G,W)` (malformed) or a deserialized
    /// point failed the subgroup membership check. The ciphertext is rejected
    /// at ingress; the submitter must re-submit a well-formed ciphertext.
    /// Never panics — always returns this error (15-SHIELD_SPEC §6).
    #[error("ciphertext is invalid: pairing validity or subgroup check failed")]
    InvalidCiphertext,

    /// The ciphertext payload exceeds the maximum permitted size.
    ///
    /// Checked at ingress (DoS pre-check) before any crypto operation.
    /// The submitter must reduce the plaintext to ≤ `max` bytes.
    #[error("payload length {len} exceeds maximum {max} bytes")]
    PayloadTooLarge { len: usize, max: usize },

    /// An arkworks serialization or deserialization error.
    ///
    /// Wraps errors from `ark_serialize` operations (point encoding/decoding,
    /// field element serialization for HKDF input). The string carries
    /// the `Debug` representation of the original `SerializationError`.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// AEAD encryption or decryption failed.
    ///
    /// ChaCha20Poly1305 errors are opaque (no plaintext details exposed).
    /// For decryption, this indicates a tampered ciphertext or wrong key.
    /// For encryption, this is practically unreachable.
    #[error("AEAD encryption/decryption failed")]
    AeadFailure,

    /// Hash-to-curve (RFC 9380) failed to map bytes to a `𝔾₂` point.
    ///
    /// Wraps the `HashToCurveError` from `ark_ec::hashing`. Practically
    /// unreachable in Shield's usage (any byte string maps successfully).
    /// Included for defensive error handling.
    #[error("hash-to-curve failed: {0}")]
    HashToCurve(String),

    // ── S3–S4: decryption shares + combine ───────────────────────────────────

    /// Fewer than `p+1` contributing shares for `combine` (§2.5, §4.2).
    ///
    /// `p = ⌊2W/3⌋` (privacy threshold). Decryption requires weight `≥ p+1`
    /// (i.e. more than 2/3 of the total committee weight). This error is a
    /// **deterministic defer** — the caller waits for more shares to arrive or
    /// treats the ciphertext as unrecoverable for this epoch.
    /// Never panics (15-SHIELD_SPEC §8, AGENTS §7.2).
    #[error("insufficient decryption shares: have weight {have}, need {need} (= p+1)")]
    InsufficientShares { have: u64, need: u64 },

    /// Validator epoch decryption key `dk_i` is zero (has no multiplicative inverse).
    ///
    /// `dk_i = 0` is computationally unreachable for an honestly generated keypair
    /// (`dk_i` is sampled uniformly from `𝔽_r \ {0}`) but is validated defensively:
    /// a zero key has no inverse, so `D_i = [dk_i^{-1}] U` is undefined.
    #[error("validator decryption key dk_i is zero (not invertible in 𝔽_r)")]
    InvalidKey,

    /// A decryption share failed the pairing validity check (§2.4).
    ///
    /// Either `e(D_i, ek_i) ≠ e(U, H)` (share does not correspond to the ciphertext
    /// and published epoch key) or the pairing tie `e(cm_i, ek_i) ≠ e(G, H)` fails.
    /// Validators that produce invalid shares are slashable (13-VALIDATOR_EPOCH §5.4).
    /// Never panics — always returns this error (15-SHIELD_SPEC §8, AGENTS §7.2).
    #[error("decryption share is invalid: pairing check failed (§2.4)")]
    InvalidShare,

    // ── S5: PVSS deal + verify ────────────────────────────────────────────────

    /// A PVSS transcript failed the §4.3 constant-term tag, FFT share, or
    /// batched multi-pairing correctness check.
    ///
    /// Returned by `pvss::verify` for any of:
    /// - Tag mismatch: `e(F_0, û₁) ≠ e(G, û₂)` — dealer's constant-term
    ///   commitment is inconsistent with the correctness tag (§4.3 step 1).
    /// - FFT/share check: batched pairing `∏ e(-G,[α]Ŷ)·e([α]A,ek_i) ≠ 1`
    ///   — an encrypted share `Ŷ_{i,ω}` is inconsistent with the polynomial
    ///   commitment expansion (§4.3 step 4).
    /// - Degenerate point: any `F_j`, `û₂`, or `Ŷ_{i,ω}` is the identity or
    ///   off the prime-order subgroup (guard chain per S2 lesson).
    /// - Tau mismatch: transcript `tau` does not match the expected epoch label
    ///   (cross-epoch replay rejection, §4.1).
    ///
    /// A dealer whose transcript fails `verify` is subject to the share-withholding
    /// slashing predicate (13-VALIDATOR_EPOCH §5.4). Never panics (§7.2).
    #[error("PVSS transcript is invalid: tag/FFT/share pairing check failed (§4.3)")]
    InvalidTranscript,

    /// A Chaum–Pedersen DLEQ proof failed verification (§3.2).
    ///
    /// One or both of the Schnorr checks failed:
    /// - `[s]U ≠ t_U + [c]D_i`  (discrete log in base `U`)
    /// - `[s]G ≠ t_G + [c]cm_i` (discrete log in base `G`)
    ///
    /// A failing DLEQ proof means the share does not come from the same `dk_i^{-1}`
    /// that was committed to in `cm_i` — i.e. the validator is cheating or the share
    /// is corrupted. Slashable per 13-VALIDATOR_EPOCH §5.4.
    #[error("decryption share DLEQ proof is invalid: Schnorr check failed (§3.2)")]
    InvalidProof,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
