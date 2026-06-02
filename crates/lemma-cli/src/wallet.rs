//! Wallet sub-commands: `lemma wallet new` and `lemma wallet address`.
//!
//! ## Storage format
//!
//! Keystores are stored as raw binary files containing
//! [`KEYSTORE_BYTE_LEN`](lemma_crypto::KEYSTORE_BYTE_LEN) = 6016 bytes:
//!
//! ```text
//! ed25519_sk (32B) ‖ mldsa65_sk (4032B) ‖ mldsa65_pk (1952B)
//! ```
//!
//! The canonical file name is `<address>.key` (e.g. `dlem1q....key`) so the
//! address is visible in the file system without loading the key.
//!
//! ## ⚠️ Security — devnet/testnet only
//!
//! Keystores are **unencrypted raw bytes**. Suitable for development and
//! local testing; mainnet keystores require password-derived encryption (KDF).
//! See Technical Debt in `living-notes.md`: "Keystore encryption — devnet only".

use std::path::{Path, PathBuf};

use lemma_core::address::{AddressType, HRP_DEVNET, HRP_MAINNET, HRP_TESTNET};
use lemma_crypto::KeyPair;

use crate::error::LemmaCliError;

// ── Network selector ─────────────────────────────────────────────────────────

/// Which network HRP to use when displaying addresses.
///
/// Devnet is the default for Phase-1 local testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

impl Network {
    /// Return the bech32m HRP for this network.
    #[must_use]
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => HRP_MAINNET,
            Network::Testnet => HRP_TESTNET,
            Network::Devnet  => HRP_DEVNET,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Devnet  => write!(f, "devnet"),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format an address as a bech32m string for the given network.
///
/// Uses `AddressType::Regular` (prefix `lem1q...`, `tlem1q...`, `dlem1q...`).
/// Returns a `String` — infallible because the HRP constants always pass
/// `Address::to_bech32`'s validation guard.
pub fn format_address(
    address: &lemma_core::Address,
    network: Network,
) -> String {
    address
        .to_bech32(network.hrp(), AddressType::Regular)
        .expect("HRP constants are always valid — encoding is infallible")
}

/// Return the canonical keystore file path for an address on a network.
///
/// Format: `<dir>/<bech32m_address>.key`
///
/// Example: `~/.lemma/wallets/dlem1q8k2d...l7wz.key`
pub fn keystore_path(
    dir: &Path,
    address: &lemma_core::Address,
    network: Network,
) -> PathBuf {
    let addr_str = format_address(address, network);
    dir.join(format!("{addr_str}.key"))
}

// ── wallet address ────────────────────────────────────────────────────────────

/// Load a keystore from `keystore_path` and return the bech32m address string.
///
/// # Errors
///
/// - [`LemmaCliError::KeystoreIo`] — file does not exist or cannot be read.
/// - [`LemmaCliError::Crypto`] — keystore bytes are invalid (wrong length or
///   corrupted key material).
pub fn address_from_keystore(
    keystore_path: &Path,
    network: Network,
) -> Result<String, LemmaCliError> {
    let bytes = std::fs::read(keystore_path)
        .map_err(|e| LemmaCliError::KeystoreIo { path: keystore_path.to_path_buf(), source: e })?;

    // Length check is canonical in from_keystore_bytes (AGENTS §2.1 — one way).
    let kp = KeyPair::from_keystore_bytes(&bytes)?;
    Ok(format_address(kp.address(), network))
}
