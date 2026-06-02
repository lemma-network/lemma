//! `lemma` — Lemma blockchain CLI.
//!
//! ## Phase 1 subcommands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `lemma wallet new [--out FILE] [--network NET]` | Generate a new hybrid keypair and save to a keystore file |
//! | `lemma wallet address --keystore FILE [--network NET]` | Print the bech32m address of an existing keystore |
//! | `lemma balance <address> [--data-dir PATH]` | Query account balance from the local chain DB |
//!
//! ## Future subcommands (later phases)
//!
//! `compile` / `deploy` / `call` — Lem smart-contract tooling (Phase 3).
//! `devnet` — single-command local devnet (Phase 4 / tooling).
//! `faucet` — request testnet tokens (Phase 4).
//!
//! ## Address format
//!
//! Lemma uses bech32m addresses. Regular user addresses start with:
//! - `lem1q...`  (mainnet)
//! - `tlem1q...` (testnet)
//! - `dlem1q...` (devnet — default for Phase 1)

mod balance;
mod error;
mod wallet;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use balance::query_balance_from_db;
use wallet::{address_from_keystore, keystore_path, Network};

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name    = "lemma",
    version,
    about   = "Lemma blockchain CLI — wallet, balance, and devnet tooling",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Wallet management: create and inspect keypairs.
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Query account balance from the local chain database.
    ///
    /// Reads the balance directly from the node's RocksDB database.
    /// Phase 4 note: will be replaced by an RPC call (lem_getBalance).
    #[command(name = "balance")]
    Balance {
        /// The account address to query (bech32m format, any network).
        address: String,

        /// Path to the chain database directory.
        ///
        /// Must point to the same directory as `--data-dir` in the running
        /// lemma-node. Defaults to `./data` for local devnet convenience.
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum WalletAction {
    /// Generate a new hybrid keypair (Ed25519 + ML-DSA-65) and save to file.
    ///
    /// ⚠️  The keystore is stored as UNENCRYPTED raw bytes.
    ///     Suitable for devnet/testnet development only.
    ///     Do NOT use for mainnet funds.
    ///
    /// Prints the new address to stdout on success.
    New {
        /// Directory where the keystore file will be written.
        ///
        /// File name: `<address>.key` (e.g. `dlem1q....key`).
        /// Directory is created if it does not exist.
        #[arg(long, default_value = "wallets")]
        out_dir: PathBuf,

        /// Network for the address display prefix.
        ///
        /// Affects only the bech32m prefix — the key material is identical.
        #[arg(long, default_value = "devnet")]
        network: Network,
    },

    /// Print the bech32m address for an existing keystore file.
    Address {
        /// Path to the keystore file (produced by `lemma wallet new`).
        #[arg(long)]
        keystore: PathBuf,

        /// Network for the address display prefix.
        #[arg(long, default_value = "devnet")]
        network: Network,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli)?;
    Ok(())
}

fn run(cli: Cli) -> Result<(), error::LemmaCliError> {
    match cli.command {
        Command::Wallet { action } => dispatch_wallet(action),
        Command::Balance { address, data_dir } => dispatch_balance(&address, &data_dir),
    }
}

// ── Wallet dispatch ───────────────────────────────────────────────────────────

fn dispatch_wallet(action: WalletAction) -> Result<(), error::LemmaCliError> {
    match action {
        WalletAction::New { out_dir, network } => {
            // Create the output directory if it does not exist.
            std::fs::create_dir_all(&out_dir).map_err(|e| error::LemmaCliError::KeystoreIo {
                path: out_dir.clone(),
                source: e,
            })?;

            let addr_str = new_wallet_in_dir(&out_dir, network)?;
            println!("{addr_str}");
            eprintln!(
                "⚠️  Keystore saved to: {}/{addr_str}.key",
                out_dir.display()
            );
            eprintln!("⚠️  UNENCRYPTED — devnet/testnet only. Do NOT use for mainnet.");
            Ok(())
        }

        WalletAction::Address { keystore, network } => {
            let addr_str = address_from_keystore(&keystore, network)?;
            println!("{addr_str}");
            Ok(())
        }
    }
}

/// Generate a keypair, derive the canonical file path from the address, save.
///
/// Extracted so the address is derived from the real keypair (not a throw-away
/// keypair), avoiding double key generation.
fn new_wallet_in_dir(
    out_dir: &std::path::Path,
    network: Network,
) -> Result<String, error::LemmaCliError> {
    use lemma_crypto::KeyPair; // local use — lemma_crypto dep is in Cargo.toml

    let kp = KeyPair::generate()?;
    let addr_str = wallet::format_address(kp.address(), network);
    let path = keystore_path(out_dir, kp.address(), network);

    // Atomic write: rename from .tmp prevents a torn file on crash.
    // Overwrite is intentional — address collision probability is negligible
    // (birthday paradox over 2^160). If you need a guard against accidental
    // overwrite (e.g. running `wallet new` twice), add a `path.exists()` check.
    let tmp_path = path.with_extension("key.tmp");
    std::fs::write(&tmp_path, kp.to_keystore_bytes()).map_err(|e| {
        error::LemmaCliError::KeystoreIo {
            path: tmp_path.clone(),
            source: e,
        }
    })?;
    std::fs::rename(&tmp_path, &path)
        .map_err(|e| error::LemmaCliError::KeystoreIo { path, source: e })?;

    Ok(addr_str)
}

// ── Balance dispatch ──────────────────────────────────────────────────────────

fn dispatch_balance(
    address_str: &str,
    data_dir: &std::path::Path,
) -> Result<(), error::LemmaCliError> {
    let (address, _addr_type, _hrp) =
        lemma_core::Address::from_bech32(address_str).map_err(|e| {
            error::LemmaCliError::InvalidAddress {
                input: address_str.to_owned(),
                reason: e.to_string(),
            }
        })?;

    let balance = query_balance_from_db(data_dir, &address)?;
    println!("{balance}  (account {address_str})");
    Ok(())
}
