//! Lemma full-node binary entry point.
//!
//! Phase 1 (N1): reads config + genesis, initialises the chain database,
//! and exits. The async block-production and P2P driver loop are added in
//! steps N3–N4.

use anyhow::Context as _;
use clap::Parser;
use lemma_node::{init_chain, InitOutcome, NodeConfig};
use lemma_storage::db::LemmaDb;
use tracing::info;

/// Command-line arguments for `lemma-node`.
#[derive(Debug, Parser)]
#[command(name = "lemma-node", about = "Lemma full node")]
struct Args {
    /// Path to the node configuration JSON file.
    #[arg(long, default_value = "config.json")]
    config: std::path::PathBuf,
}

fn main() -> anyhow::Result<()> {
    // ── Tracing setup ─────────────────────────────────────────────────────────
    tracing_subscriber::fmt::init();

    // ── Load + validate config ────────────────────────────────────────────────
    let args = Args::parse();
    let cfg = NodeConfig::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;
    cfg.validate().context("config validation")?;

    // ── Load genesis config ───────────────────────────────────────────────────
    let genesis_bytes = std::fs::read_to_string(&cfg.genesis_path)
        .with_context(|| format!("reading genesis from {}", cfg.genesis_path.display()))?;
    let genesis: lemma_core::genesis::GenesisConfig = serde_json::from_str(&genesis_bytes)
        .context("parsing genesis JSON")?;

    // ── Open / create the chain database ─────────────────────────────────────
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("creating data_dir {}", cfg.data_dir.display()))?;
    let db = LemmaDb::open(&cfg.data_dir)
        .with_context(|| format!("opening database at {}", cfg.data_dir.display()))?;

    // ── Initialise chain (idempotent) ─────────────────────────────────────────
    match init_chain(db, &genesis).context("genesis boot")? {
        InitOutcome::Initialized { genesis_hash, accounts } => {
            info!(
                genesis_hash = %genesis_hash.to_hex(),
                accounts,
                "chain initialised"
            );
        }
        InitOutcome::AlreadyInitialized { height } => {
            info!(height, "chain already initialised — skipping genesis");
        }
    }

    // N3 will replace this with the async block-production + P2P event loop.
    info!("lemma-node N1 complete — async driver not yet wired (N3)");
    Ok(())
}
