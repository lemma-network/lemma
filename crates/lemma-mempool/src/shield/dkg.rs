//! # Shield DKG Driver — BFT-native aggregatable PVSS-DKG (S6)
//!
//! Implements the single-shot BFT DKG driver (15-SHIELD_SPEC §4.6).
//! A **pure deterministic state machine**: no async, no I/O, no CSPRNG.
//! Signature validity is injected as a `bool` per the DB-7 pattern —
//! the driver does NOT call `lemma-crypto` directly, staying crypto-free
//! at the orchestration boundary (DB-12).
//!
//! ## Determinism (§7)
//!
//! Dealer selection is sorted by `(weight desc, Address asc)` — a canonical
//! total order independent of insertion order. Same posted set → same `Y`
//! and same `selected_dealers` on every honest node. The committed block
//! makes the selection canonical regardless (§4.6 step 3).
//!
//! ## Clean-room provenance (DB-11)
//!
//! Derived from the **GJMMST Aggregatable-DKG** paper (Gurkan–Jovanovic–
//! Maller–Meiklejohn–Stern–Tomescu) and 15-SHIELD_SPEC §4.6. The GPL-3.0
//! ferveo codebase was **never read or referenced** (AGENTS §9.3).
//!
//! ## Crate-dependency note (DB-12)
//!
//! `run_dkg` is a pure crypto function exposed by `lemma-mempool`. The
//! cross-crate wiring — driving DKG at epoch boundaries, feeding
//! `faulty_dealers` into `lemma-consensus::slashing` — is orchestrated by
//! the `lemma-node` layer. Consensus is crypto-free and cannot depend on
//! Shield (`lemma-mempool`); that would invert the dependency direction
//! (AGENTS §8).

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{G1Affine, G2Affine};
use lemma_core::address::Address;

use crate::shield::{
    committee::ShieldCommittee,
    pvss::{aggregate, verify, PvssTranscript},
    ShieldError,
};

// ── DkgOutput ─────────────────────────────────────────────────────────────────

/// Result of a successful DKG round (15-SHIELD_SPEC §4.6).
///
/// ## Invariant
///
/// `y == aggregate.coeff_comms[0]`: the epoch public key is always the
/// constant-term commitment `F_0` of the aggregated transcript.
///
/// ## Usage (by the `lemma-node` layer)
///
/// 1. Commit `aggregate` in the next block (fixes the transcript for all nodes).
/// 2. Publish `y` as the epoch threshold public key (clients encrypt to `y`).
/// 3. Each validator calls `recover_share(dk_i, &aggregate, share_ids)` to
///    get their `Z_{i,ω}` shares for TPKE combine (§4.5).
/// 4. Report `faulty_dealers` to `lemma-consensus::slashing` (13 §5.4).
#[derive(Debug, Clone)]
pub struct DkgOutput {
    /// Epoch threshold public key `Y = F_0 ∈ 𝔾₁`.
    pub y: G1Affine,
    /// Aggregated PVSS transcript — fixed by the committed block; all nodes derive
    /// the same `Y` and the same `Z_{i,ω}` from this (§7, §4.6 step 3).
    pub aggregate: PvssTranscript,
    /// Dealer addresses whose transcripts were selected and aggregated (≥ 2/3 W).
    /// `BTreeSet` guarantees deterministic ordering (§7.1).
    pub selected_dealers: BTreeSet<Address>,
    /// Dealers whose transcripts failed `verify` (§4.3) or were posted with
    /// `sig_ok = false`. Recorded for the share-withholding slashing predicate
    /// (13-SHIELD_SPEC §5.4). Injected as `bool` flags by the node layer (DB-7).
    pub faulty_dealers: BTreeSet<Address>,
}

// ── run_dkg ───────────────────────────────────────────────────────────────────

/// Drive the BFT-native aggregatable PVSS-DKG from posted dealer transcripts (§4.6).
///
/// ## Steps (all deterministic — same inputs → byte-identical output)
///
/// 1. **Sig filter** (injected, DB-7): discard dealers where `sig_ok = false`
///    and add them to `faulty_dealers`.
/// 2. **Transcript verify**: run [`verify`] (§4.3) on each remaining dealer in
///    canonical `BTreeMap<Address, …>` iteration order (§7.1).
///    Verification failures → `faulty_dealers`.
/// 3. **Deterministic selection**: sort survivors by `(weight desc, Address asc)`;
///    accumulate until `≥ ⌈2/3·W⌉`. Stop as soon as threshold is reached.
/// 4. **Aggregate** (§4.4): call [`aggregate`] on the selected set.
/// 5. **Return** `DkgOutput { y: F_0, aggregate, selected_dealers, faulty_dealers }`.
///
/// ## Arguments
///
/// * `posted` — dealer address → `(PvssTranscript, sig_ok: bool)`.
///   `sig_ok` is the injected signature-validity result (DB-7).
/// * `committee` — the current epoch committee (weight + share-IDs source).
/// * `eks` — `validator_index → ek_i = [dk_i]H ∈ 𝔾₂` epoch public keys.
///   Index = 0-based position in `committee.iter()` (canonical address order).
///   Passed by the caller — node owns per-epoch key storage (DB-12).
/// * `tau` — expected epoch label; every transcript must carry exactly this `tau`.
///
/// ## Errors
///
/// - [`ShieldError::DkgQuorumNotReached`] — surviving valid transcripts total
///   weight `< ⌈2/3·W⌉`. Epoch proceeds with the last good `Y` (§6, no crash).
pub fn run_dkg(
    posted: &BTreeMap<Address, (PvssTranscript, bool)>,
    committee: &ShieldCommittee,
    eks: &BTreeMap<u16, G2Affine>,
    tau: &[u8],
) -> Result<DkgOutput, ShieldError> {
    let total_w = committee.total_weight();
    // Quorum = ⌈2/3·W⌉.  Integer ceiling: ⌈2W/3⌉ = (2W + 2) / 3.
    // Saturate on overflow (W ≤ 65 535, so 2W ≤ 131 070 — well within u64).
    let quorum = total_w
        .checked_mul(2)
        .map(|v| v.div_ceil(3))
        .unwrap_or(u64::MAX);

    let mut valid: Vec<(Address, PvssTranscript, u64)> = Vec::new();
    let mut faulty: BTreeSet<Address> = BTreeSet::new();

    // ── Steps 1–2: sig filter then transcript verify ──────────────────────────
    // BTreeMap iteration order is deterministic canonical address order (§7.1).
    for (addr, (tr, sig_ok)) in posted {
        if !sig_ok {
            faulty.insert(*addr);
            continue;
        }
        match verify(tau, tr, committee, eks) {
            Ok(()) => {
                let weight = committee.weight_of(addr);
                valid.push((*addr, tr.clone(), weight));
            }
            Err(_) => {
                faulty.insert(*addr);
            }
        }
    }

    // ── Step 3: deterministic selection — (weight desc, Address asc) ─────────
    // `sort_by` is deterministic (not sort_unstable_by — must be stable enough
    // for the secondary Address key to produce a total order). The Address
    // tiebreak makes the sort total: equal-weight validators always appear in
    // the same canonical order on every node.
    valid.sort_by(|(a_addr, _, a_w), (b_addr, _, b_w)| {
        b_w.cmp(a_w).then_with(|| a_addr.cmp(b_addr))
    });

    let mut selected_dealers: BTreeSet<Address> = BTreeSet::new();
    let mut selected_transcripts: Vec<PvssTranscript> = Vec::new();
    let mut accumulated: u64 = 0;

    for (addr, tr, weight) in valid {
        if accumulated >= quorum {
            break; // threshold already satisfied — stop adding dealers
        }
        selected_dealers.insert(addr);
        selected_transcripts.push(tr);
        accumulated = accumulated.saturating_add(weight);
    }

    if accumulated < quorum {
        return Err(ShieldError::DkgQuorumNotReached {
            have: accumulated,
            need: quorum,
        });
    }

    // ── Step 4: aggregate selected transcripts (§4.4) ─────────────────────────
    let agg = aggregate(&selected_transcripts)?;
    // Y = F_0 = aggregate constant-term commitment ∈ 𝔾₁ (§4.4, §1.2).
    let y = agg.coeff_comms[0];

    Ok(DkgOutput {
        y,
        aggregate: agg,
        selected_dealers,
        faulty_dealers: faulty,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
