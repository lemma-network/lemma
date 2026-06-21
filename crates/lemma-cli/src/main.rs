// `LemmaCliError` contains a `LangError` variant (144 bytes). The CLI is not a
// hot path and the ergonomics of a flat enum outweigh the stack-size concern —
// same rationale as `lemma-lang/src/lib.rs`. Suppressed crate-wide.
#![allow(clippy::result_large_err)]
//! `lemma` — Lemma blockchain CLI.
//!
//! ## Subcommands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `lemma compile <file.lem> [--output-dir DIR]` | Compile a Lem contract → .wasm + .abi.json + .meta.json |
//! | `lemma wallet new [--out-dir DIR] [--network NET]` | Generate a new hybrid keypair and save to a keystore file |
//! | `lemma wallet address --keystore FILE [--network NET]` | Print the bech32m address of an existing keystore |
//! | `lemma balance <address> [--data-dir PATH]` | Query account balance from the local chain DB |
//!
//! ## Future subcommands (later phases)
//!
//! `deploy` / `call` — on-chain contract interaction (Phase 4 / RPC).
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
mod compile;
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
    /// Compile a Lem smart contract to WASM, ABI, and metadata.
    ///
    /// Runs the full Lem compiler pipeline on the input `.lem` file:
    ///   tokenize → parse → type-check → well-formedness → safety analysis → codegen
    ///
    /// Three output files are written per contract in the source:
    ///   {name}.wasm      — WASM binary (deploy this to LemmaVM)
    ///   {name}.abi.json  — ABI descriptor (function selectors + types)
    ///   {name}.meta.json — contract metadata (compiler version, safety ruleset,
    ///                      per-function state-access hints, runtime constraints)
    #[command(name = "compile")]
    Compile {
        /// Path to the `.lem` source file to compile.
        file: PathBuf,

        /// Directory to write output files into.
        ///
        /// Three files are written per contract: `{name}.wasm`,
        /// `{name}.abi.json`, `{name}.meta.json`. The directory is
        /// created if it does not exist. Defaults to the directory
        /// containing the input file.
        #[arg(long, short = 'o')]
        output_dir: Option<PathBuf>,
    },

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
        Command::Compile { file, output_dir } => dispatch_compile(&file, output_dir.as_deref()),
        Command::Wallet { action } => dispatch_wallet(action),
        Command::Balance { address, data_dir } => dispatch_balance(&address, &data_dir),
    }
}

// ── Compile dispatch ──────────────────────────────────────────────────────────

fn dispatch_compile(
    source_path: &std::path::Path,
    output_dir: Option<&std::path::Path>,
) -> Result<(), error::LemmaCliError> {
    // Default output dir: same directory as the input file; fall back to ".".
    let dir = output_dir
        .map(std::path::Path::to_owned)
        .or_else(|| source_path.parent().map(std::path::Path::to_owned))
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let outputs = compile::compile_contract(source_path, &dir)?;

    if outputs.is_empty() {
        eprintln!("warning: no contracts found in '{}'", source_path.display());
    }
    for out in &outputs {
        println!("{}", out.wasm.display());
        println!("{}", out.abi_json.display());
        println!("{}", out.meta_json.display());
    }
    Ok(())
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
