//! Lemma full-node binary entry point.
//!
//! ## Boot sequence (Phase 1 N3)
//!
//! ```text
//! 1. Parse CLI args → load + validate NodeConfig
//! 2. Parse GenesisConfig from JSON
//! 3. init_chain (one-time setup, separate LemmaDb handle — consumed + dropped)
//! 4. Re-open LemmaDb as Arc<LemmaDb> (shared runtime handle)
//! 5. Create Arc<RwLock<Mempool>> (N4 network ingress will write to this)
//! 6. Wire shutdown signal (watch channel + CTRL+C handler)
//! 7. Spawn producer loop → run until shutdown
//! ```
//!
//! ## Phase 2 forward note
//!
//! In Phase 2, step 7 is replaced by the Surge/Pulse DAG consensus driver.
//! The `Arc<LemmaDb>` and `Arc<RwLock<Mempool>>` handles established here
//! are already correctly shaped for multi-task sharing (see `chain.rs`
//! module doc for the write-serialization contract).

use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use tokio::sync::RwLock;
use tracing::info;

use lemma_core::{address::Address, genesis::GenesisConfig};
use lemma_mempool::pool::Mempool;
use lemma_node::{init_chain, InitOutcome, NodeConfig, ProducerConfig, run_producer};
use lemma_storage::db::LemmaDb;

/// Mempool capacity for Phase 1 single-node operation.
///
/// Conservative limit: 10_000 pending transactions is well above single-node
/// throughput. Phase 2 will parameterise this from NodeConfig.
const MEMPOOL_CAPACITY: usize = 10_000;

/// Command-line arguments for `lemma-node`.
#[derive(Debug, Parser)]
#[command(name = "lemma-node", about = "Lemma full node — Phase 1 single-node producer")]
struct Args {
    /// Path to the node configuration JSON file.
    #[arg(long, default_value = "config.json")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Tracing ───────────────────────────────────────────────────────────────
    tracing_subscriber::fmt::init();

    // ── Config ────────────────────────────────────────────────────────────────
    let args = Args::parse();
    let cfg  = NodeConfig::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;
    cfg.validate().context("config validation")?;

    // ── Genesis ───────────────────────────────────────────────────────────────
    let genesis_bytes = std::fs::read_to_string(&cfg.genesis_path)
        .with_context(|| format!("reading genesis from {}", cfg.genesis_path.display()))?;
    let genesis: GenesisConfig = serde_json::from_str(&genesis_bytes)
        .context("parsing genesis JSON")?;

    // ── Step 3: init chain (one-time, separate handle) ────────────────────────
    // init_chain consumes its LemmaDb handle (WorldState ownership model).
    // The DB is dropped at the end of init_chain; we re-open below.
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("creating data_dir {}", cfg.data_dir.display()))?;

    match init_chain(LemmaDb::open(&cfg.data_dir)
        .with_context(|| format!("opening init DB at {}", cfg.data_dir.display()))?,
        &genesis)
        .context("genesis boot")?
    {
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

    // ── Step 4: runtime DB handle (re-open as Arc for multi-task sharing) ─────
    // All subsequent tasks share this handle. Write exclusivity is enforced
    // by callers (see chain.rs N3 forward note).
    let db = Arc::new(
        LemmaDb::open(&cfg.data_dir)
            .with_context(|| format!("opening runtime DB at {}", cfg.data_dir.display()))?,
    );

    // ── Step 5: mempool ───────────────────────────────────────────────────────
    // RwLock: producer holds write lock per tick; N4 network-ingress task
    // will acquire write lock to admit incoming transactions.
    let mempool = Arc::new(RwLock::new(Mempool::new(MEMPOOL_CAPACITY)));

    // ── Step 6: shutdown signal ───────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let tx_ctrlc = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
        info!("CTRL+C received — signalling shutdown");
        let _ = tx_ctrlc.send(true);
    });

    // ── Step 7: producer loop ─────────────────────────────────────────────────
    // Phase 1 proposer: zero address (no keypair yet — N7/CLI derives from
    // a real keypair; the proposer field is carried in the block header for
    // Phase 2 reward routing, but is not validated in Phase 1 single-node mode).
    let proposer     = Address::zero();
    let producer_cfg = ProducerConfig { block_interval_ms: cfg.block_interval_ms };

    info!(
        block_interval_ms = cfg.block_interval_ms,
        "starting single-node producer (Phase 1)"
    );

    run_producer(db, mempool, producer_cfg, proposer, shutdown_rx)
        .await
        .context("producer error")?;

    info!("lemma-node shutdown complete");
    Ok(())
}
