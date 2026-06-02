//! # Shield — Lemma encrypted mempool (decrypt-after-order MEV protection)
//!
//! Threshold public-key encryption + aggregatable PVSS-DKG + per-epoch
//! proactive resharing over **BLS12-381**. Implements the "decrypt-after-order"
//! guarantee: ciphertexts are ordered by consensus while opaque; the plaintext
//! is released only after 2f+1 finality, defeating MEV and front-running.
//!
//! ## Clean-room provenance (decisions-log DB-11)
//!
//! Algorithms are derived from:
//! - **Ferveo paper** (IACR ePrint 2022/898, Bebel & Ojha — CC-BY-NC-ND prose;
//!   read for algorithmic understanding only. The GPL-3.0 ferveo *code* was
//!   **never read or referenced** — AGENTS.md §9.3).
//! - **GJMMST Aggregatable-DKG** — aggregation soundness.
//! - **Herzberg et al., "Proactive Secret Sharing"** — per-epoch resharing.
//! - **Baek–Zheng GDH threshold cryptosystem** — IND-CCA2 TPKE.
//!
//! Reusable primitives: docknetwork `secret_sharing_and_dkg` 0.16.0,
//! `schnorr_pok` 0.23.0, `dock_crypto_utils` 0.23.0 (Apache-2.0); arkworks
//! 0.4.x (MIT/Apache). Licenses verified live 2026-06-02 (DB-11).
//!
//! ## Crate-dependency note (DB-12)
//!
//! Shield's BLS12-381 pairing crypto is **self-contained in this module** over
//! arkworks — it is NOT part of `lemma-crypto` (Ed25519+ML-DSA+Blake3 only).
//! The DKG driver and resharing are pure crypto functions; cross-crate wiring
//! (epoch-boundary trigger, share-withholding feedback to consensus slashing)
//! is orchestrated by the `lemma-node` layer. See 15-SHIELD_SPEC §4.6, §5.3.
//!
//! ## Module map
//!
//! | Module | Sub-step | Contents |
//! |--------|----------|----------|
//! | `error` | S1 | [`ShieldError`] — all error variants |
//! | `params` | S1 | [`ShieldParams`] + frozen DST/HKDF constants |
//! | `committee` | S1 | [`ShieldCommittee`] + Ω_i stake-weighted partition |
//! | `domain` | S1 | [`ShieldDomain`] — fixed FFT domain + Lagrange cache |
    //! | `ciphertext` | S2 | `Ciphertext` wire layout + AEAD + subgroup checks |
    //! | `tpke` | S2, S4 | encrypt / validate / combine |
    //! | `share` | S3 ✅ | `DecryptionShare` + `decryption_share` + `verify_share` + `verify_share_batch` |
//! | `pvss` | S5–S6 | PVSS transcript + FFT verify + aggregate |
//! | `dkg` | S6 | BFT-native DKG driver |
//! | `pss` | S7 | Per-epoch zero-secret resharing |
//!
//! See `docs/15-SHIELD_SPEC.md` for the full cryptographic specification.
//! See `docs/11-MEMPOOL_SHIELD_SPEC.md` for mempool integration and launch posture.

pub mod ciphertext;
pub mod committee;
pub mod domain;
pub mod error;
pub mod params;
pub mod share;
pub mod tpke;

pub use ciphertext::{Ciphertext, ShieldAad};
pub use error::ShieldError;
pub use share::{DecryptionShare, ShareProof};
