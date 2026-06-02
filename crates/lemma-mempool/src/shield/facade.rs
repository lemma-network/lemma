//! # Shield facade (S8) — unified API + share-withholding predicate
//!
//! Assembles the S1–S7 crypto primitives behind one [`Shield`] handle and
//! exposes the share-withholding predicate (15-SHIELD_SPEC §8.1, §4.3/§5.4).
//!
//! ## Decrypt-after-order lifecycle
//!
//! 1. **DKG** ([`Shield::run_dkg`]): drive the epoch DKG → epoch key `Y` + per-validator
//!    `Z_{i,ω}`. Call [`Shield::set_epoch_key`] with the resulting `Y`.
//! 2. **Encrypt** ([`Shield::encrypt`], client-side): client encrypts a tx to `Y`.
//! 3. **Ingress** ([`Shield::validate_ingress`]): DoS pre-check on submission.
//! 4. **Order**: consensus orders the opaque ciphertext (outside Shield).
//! 5. **Decrypt-after-final** ([`Shield::decryption_share`] then [`Shield::decrypt`]):
//!    once the order is final, validators release shares; any node combines ≥ p+1
//!    weight → plaintext.
//! 6. **Reshare** ([`Shield::reshare`]): at the epoch boundary, refresh shares to the
//!    new committee while keeping `Y` invariant.
//!
//! ## Crate-dependency note (DB-12)
//!
//! All methods are **pure crypto / pure functions** — no async, no I/O, no
//! cross-crate calls. The `lemma-node` layer drives *when* DKG/resharing runs
//! (epoch trigger, post-settlement `ValidatorSet(N+1)`) and feeds the
//! [`withholding_set`] result into `lemma-consensus::slashing` as injected
//! data (DB-12). Consensus stays crypto-free; the node is the orchestrator.

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use lemma_core::address::Address;

use crate::shield::{
    ciphertext::{Ciphertext, ShieldAad},
    committee::ShieldCommittee,
    dkg::{run_dkg, DkgOutput},
    domain::ShieldDomain,
    params::ShieldParams,
    pss::verify_reshare,
    pvss::{aggregate, PvssTranscript},
    share::{decryption_share, DecryptionShare},
    tpke::{combine, encrypt, validate, CombineShare},
    ShieldError,
};

// ── Shield handle ─────────────────────────────────────────────────────────────

/// Stateful Shield handle for one epoch (15-SHIELD_SPEC §8.1).
///
/// Holds the epoch committee, its Lagrange/FFT domain (built once), and the
/// epoch threshold public key `Y` (`None` until DKG completes). `ShieldParams`
/// is reachable via [`Shield::params`] (no duplication — single source of truth
/// in the committee, DB-17 minimalism: `Y` is a bare `G1Affine`, no newtype).
#[derive(Clone, Debug)]
pub struct Shield {
    committee: ShieldCommittee,
    domain: ShieldDomain,
    /// Epoch threshold public key `Y = F_0 ∈ 𝔾₁` — `None` until DKG completes.
    epoch_key: Option<G1Affine>,
}

impl Shield {
    /// Construct a Shield handle for `committee` (epoch key unset).
    ///
    /// Builds the Lagrange/FFT domain once from the committee's total weight.
    ///
    /// # Errors
    ///
    /// - [`ShieldError::DomainTooLarge`] — `W > u16::MAX` (65 535).
    /// - [`ShieldError::FftDomainFailed`] — FFT domain construction failed (unreachable for valid W).
    pub fn new(committee: ShieldCommittee) -> Result<Self, ShieldError> {
        let domain = ShieldDomain::new(committee.total_weight())?;
        Ok(Self { committee, domain, epoch_key: None })
    }

    /// Set the epoch threshold public key `Y` after DKG completes (§4.6).
    pub fn set_epoch_key(&mut self, y: G1Affine) {
        self.epoch_key = Some(y);
    }

    /// The epoch threshold public key `Y`, or `None` before DKG completes.
    #[must_use]
    pub fn epoch_key(&self) -> Option<&G1Affine> {
        self.epoch_key.as_ref()
    }

    /// The epoch committee.
    #[must_use]
    pub fn committee(&self) -> &ShieldCommittee {
        &self.committee
    }

    /// The threshold parameters `(W, t, p)` (via the committee — single source of truth).
    #[must_use]
    pub fn params(&self) -> &ShieldParams {
        self.committee.params()
    }

    // ── Client-side encryption ────────────────────────────────────────────────

    /// Encrypt `msg` to the epoch public key `y` (15-SHIELD_SPEC §2.1).
    ///
    /// **Associated function** (no `&self`): clients encrypt without holding a
    /// `Shield` instance — they only need the published epoch key `y` and the AAD.
    /// Delegates to [`tpke::encrypt`].
    ///
    /// # Errors
    ///
    /// - [`ShieldError::PayloadTooLarge`] — `msg` exceeds `MAX_SHIELD_PAYLOAD_BYTES`.
    /// - [`ShieldError::HashToCurve`] / [`ShieldError::AeadFailure`] — unreachable in practice.
    pub fn encrypt(y: &G1Affine, aad: ShieldAad, msg: &[u8]) -> Result<Ciphertext, ShieldError> {
        encrypt(y, aad, msg)
    }

    // ── Ingress validation (DoS pre-check) ─────────────────────────────────────

    /// Validate a submitted ciphertext at ingress (15-SHIELD_SPEC §2.2).
    ///
    /// A cheap pairing + subgroup check rejecting malformed ciphertexts before
    /// they enter the mempool (DoS protection). Delegates to [`tpke::validate`].
    ///
    /// # Errors
    ///
    /// [`ShieldError::InvalidCiphertext`] — validity pairing or subgroup check failed.
    pub fn validate_ingress(&self, ct: &Ciphertext) -> Result<(), ShieldError> {
        validate(ct)
    }

    // ── Settlement path: decryption share + combine ────────────────────────────

    /// Produce this validator's decryption share + DLEQ proof (15-SHIELD_SPEC §2.3, §3).
    ///
    /// Called **only after** the ciphertext's order is final (§4.4 — premature
    /// release is a protocol violation). `validator_index` is the validator's
    /// 0-based position in `committee.iter()`. Delegates to [`share::decryption_share`].
    ///
    /// # Errors
    ///
    /// - [`ShieldError::InvalidKey`] — `dk_i == 0`.
    /// - [`ShieldError::Serialization`] — FS transcript serialization failed.
    pub fn decryption_share(
        &self,
        dk_i: &Fr,
        validator_index: u16,
        ct: &Ciphertext,
    ) -> Result<DecryptionShare, ShieldError> {
        decryption_share(dk_i, validator_index, ct)
    }

    /// Combine ≥ p+1 weight of recovered key shares → plaintext (15-SHIELD_SPEC §2.5).
    ///
    /// Takes [`CombineShare`]s carrying the recovered `Z_{i,ω}` group-element shares
    /// (from [`pvss::recover_share`] / [`pss::combine_shares`]) — **not** the S3
    /// `DecryptionShare` accountability tokens (see the S4 spec correction: `combine`
    /// uses `Z`, not `D_i`). Delegates to [`tpke::combine`] with this handle's domain.
    ///
    /// # Errors
    ///
    /// - [`ShieldError::InsufficientShares`] — contributing weight `< p+1`.
    /// - [`ShieldError::Lagrange`] — invalid share-ID subset.
    /// - [`ShieldError::AeadFailure`] — wrong key or tampered payload.
    pub fn decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[CombineShare],
    ) -> Result<Vec<u8>, ShieldError> {
        combine(ct, shares, &self.committee, &self.domain)
    }

    // ── Epoch DKG ──────────────────────────────────────────────────────────────

    /// Drive the epoch aggregatable PVSS-DKG (15-SHIELD_SPEC §4.6).
    ///
    /// Delegates to [`dkg::run_dkg`] with this handle's committee. `posted` maps
    /// each dealer's `Address` to its `(transcript, sig_ok)`; `sig_ok` is the
    /// injected signature-validity result (DB-7). `eks` are the epoch public keys
    /// (validator-index → `ek_i`); `tau` is the DKG epoch label.
    ///
    /// After success, call [`Shield::set_epoch_key`] with `DkgOutput::y`.
    ///
    /// # Errors
    ///
    /// [`ShieldError::DkgQuorumNotReached`] — valid transcripts total weight `< ⌈2/3·W⌉`.
    pub fn run_dkg(
        &self,
        posted: &BTreeMap<Address, (PvssTranscript, bool)>,
        eks: &BTreeMap<u16, G2Affine>,
        tau: &[u8],
    ) -> Result<DkgOutput, ShieldError> {
        run_dkg(posted, &self.committee, eks, tau)
    }

    // ── Epoch-boundary resharing ───────────────────────────────────────────────

    /// Reshare the epoch key `Y` to the new (post-settlement) committee (15-SHIELD_SPEC §5).
    ///
    /// BFT-native resharing driver (analogue of [`Shield::run_dkg`] for PSS):
    ///
    /// 1. Sig-filter posted reshare transcripts (`sig_ok`, DB-7).
    /// 2. [`pss::verify_reshare`] each survivor against `new_committee` (§5.4 —
    ///    asserts `F_0 == 𝒪 ∧ tag == 𝒪`, rejecting any shift-`Y` attack).
    /// 3. Select by `(weight desc, Address asc)` until `≥ ⌈2/3·W_new⌉` (deterministic).
    /// 4. [`pvss::aggregate`] the selected zero-transcripts.
    ///
    /// `Y` is **unchanged** (every selected transcript has `F_0 == 𝒪` ⇒ aggregate
    /// `F_0 == 𝒪`). Validators recover `Z_zero` from `DkgOutput::aggregate` and add
    /// it to their old shares via [`pss::combine_shares`] (§5.1 step 3, off this path).
    ///
    /// **Weight reference**: `new_committee.weight_of(addr)` — a dealer that is a
    /// member of the new committee contributes its new weight; an old-committee
    /// dealer absent from the new committee contributes weight 0 (correctly excluded).
    ///
    /// `DkgOutput::y` is set to the aggregate's `F_0` (the identity 𝒪) — callers keep
    /// using the *old* `Y` (key-invariance); the resharing output's `y` is only the
    /// zero-aggregate constant term, not a new epoch key.
    ///
    /// # Errors
    ///
    /// [`ShieldError::DkgQuorumNotReached`] — valid reshare transcripts weight `< ⌈2/3·W_new⌉`.
    pub fn reshare(
        &self,
        new_committee: &ShieldCommittee,
        posted: &BTreeMap<Address, (PvssTranscript, bool)>,
        eks_new: &BTreeMap<u16, G2Affine>,
        tau: &[u8],
    ) -> Result<DkgOutput, ShieldError> {
        let total_w = new_committee.total_weight();
        // Quorum = ⌈2/3·W_new⌉ (same formula as run_dkg, §4.6 / §5.2).
        let quorum = total_w.checked_mul(2).map(|v| v.div_ceil(3)).unwrap_or(u64::MAX);

        // TODO(shield): if a 3rd DKG-style driver appears, extract a shared
        // `select_to_quorum(survivors, quorum)` helper (AGENTS §2.1). Two call-sites
        // (run_dkg + reshare) with a differing inner verify step is below the
        // 3-concrete-cases threshold (§17 premature-abstraction guard) — keep parallel.

        let mut valid: Vec<(Address, PvssTranscript, u64)> = Vec::new();
        let mut faulty: BTreeSet<Address> = BTreeSet::new();

        // Steps 1–2: sig-filter, then verify_reshare each (canonical address order, §7.1).
        for (addr, (tr, sig_ok)) in posted {
            if !sig_ok {
                faulty.insert(*addr);
                continue;
            }
            match verify_reshare(tau, tr, new_committee, eks_new) {
                Ok(()) => {
                    let weight = new_committee.weight_of(addr);
                    valid.push((*addr, tr.clone(), weight));
                }
                Err(_) => {
                    faulty.insert(*addr);
                }
            }
        }

        // Step 3: deterministic selection — (weight desc, Address asc).
        valid.sort_by(|(a_addr, _, a_w), (b_addr, _, b_w)| {
            b_w.cmp(a_w).then_with(|| a_addr.cmp(b_addr))
        });

        let mut selected_dealers: BTreeSet<Address> = BTreeSet::new();
        let mut selected_transcripts: Vec<PvssTranscript> = Vec::new();
        let mut accumulated: u64 = 0;
        for (addr, tr, weight) in valid {
            if accumulated >= quorum {
                break;
            }
            selected_dealers.insert(addr);
            selected_transcripts.push(tr);
            accumulated = accumulated.saturating_add(weight);
        }

        if accumulated < quorum {
            return Err(ShieldError::DkgQuorumNotReached { have: accumulated, need: quorum });
        }

        // Step 4: aggregate the selected zero-transcripts (§4.4 reused).
        let agg = aggregate(&selected_transcripts)?;
        // y = aggregate F_0 = 𝒪 (resharing is zero-secret — Y is invariant, taken
        // from the pre-existing epoch key, not from this output).
        let y = agg.coeff_comms[0];

        Ok(DkgOutput { y, aggregate: agg, selected_dealers, faulty_dealers: faulty })
    }
}

// ── dealer non-contribution predicate (Duty A — §4.6 dealer duty) ─────────────

/// Compute the set of committee members that **failed to contribute** a valid
/// transcript in a DKG or resharing round (15-SHIELD_SPEC §4.6 dealer duty;
/// the "Duty A" half of the share-withholding accountability surface).
///
/// A **non-contributor** is any committee member that either:
/// - **never posted** a transcript (absent from `posted`), or
/// - **posted an invalid one** (present in `dkg.faulty_dealers` — `sig_ok = false`
///   or failed `verify` / `verify_reshare`).
///
/// ```text
/// non_contributors = (committee \ posted.keys())  ∪  (faulty_dealers ∩ committee)
/// ```
///
/// ## Why NOT `committee \ selected_dealers`
///
/// `DkgOutput::selected_dealers` is **quorum-truncated**: `run_dkg`/`reshare` stop
/// selecting once `≥ ⌈2/3·W⌉` weight is reached (§4.6 step b). An **honest** dealer
/// that posted a perfectly valid transcript but was simply *not needed* to reach
/// quorum is absent from `selected_dealers` — yet it withheld nothing. Using
/// `committee \ selected_dealers` would wrongly flag honest validators for the
/// 10 % slash every epoch. This predicate uses the actual `posted` set + the
/// `faulty_dealers` record instead, so honest-but-unselected dealers are **not**
/// flagged. (Corrects the stale `selected_dealers` assumption in living-notes W-2.)
///
/// ## Scope — Duty A only; Duty B is the node's job
///
/// This is the **dealer-contribution** predicate (DKG/reshare-round transcript
/// posting). It is **NOT** the full §5.4 share-withholding slashing law, which
/// slashes **decryption-share non-release for a *finalized* ciphertext** within
/// `SHARE_RELEASE_DEADLINE` rounds, evidenced by `≥ 2f+1`-attested accusations
/// (11 §4.3 / 13 §5.4). That "Duty B" predicate is **evidence/accusation-driven**,
/// needs finality + deadline + outage-attestation data that does not exist at the
/// crypto layer, and is built at the `lemma-node` layer (reusing the existing
/// `lemma-consensus::slashing::evidence` accusation-dedup infrastructure). See
/// living-notes "Duty B" deferred-debt and DB-12.
///
/// The node maps this `BTreeSet<Address>` to the slashing input
/// `BTreeMap<ValidatorId, bool>` fed to `lemma-consensus::slashing`
/// (`SHARE_WITHHOLDING_SLASH_BPS = 1000` → 10 %, finite jail). This function is
/// **pure** — it performs no slashing itself, and re-runs no crypto (it trusts the
/// `faulty_dealers` already computed by `run_dkg`/`reshare`).
///
/// Determinism (§7): `BTreeSet` iteration is canonical address order; same inputs
/// → same output on every node.
#[must_use]
pub fn withholding_set(
    committee: &ShieldCommittee,
    posted: &BTreeMap<Address, (PvssTranscript, bool)>,
    dkg: &DkgOutput,
) -> BTreeSet<Address> {
    committee
        .iter()
        .map(|(addr, _)| *addr)
        .filter(|addr| {
            // Non-contributor iff: never posted, OR posted but flagged faulty.
            !posted.contains_key(addr) || dkg.faulty_dealers.contains(addr)
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
