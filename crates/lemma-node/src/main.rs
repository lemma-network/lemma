//! Lemma full-node binary entry point.
//!
//! ## Boot sequence (Phase 1 N4)
//!
//! ```text
//! 1. Parse CLI args → load + validate NodeConfig
//! 2. Parse GenesisConfig from JSON
//! 3. init_chain (one-time setup, separate LemmaDb handle — consumed + dropped)
//! 4. Re-open LemmaDb as Arc<LemmaDb> (shared runtime handle)
//! 5. Create Arc<RwLock<Mempool>>
//! 6. Wire shutdown signal (watch channel + CTRL+C handler)
//! 7. Build NetworkConfig from NodeConfig + start NetworkService
//! 8. Wire committed-block channel (producer → broadcaster)
//! 9. Spawn four tasks and join: network_service, block_broadcaster,
//!    network_dispatch, producer
//! ```
//!
//! ## Task topology
//!
//! ```text
//!                   ┌─────────────────────────┐
//!                   │   NetworkService::run    │ ← owns Swarm
//!                   │   (lemma-network)        │
//!                   └──────────┬──────────────┘
//!                 NetworkHandle│           NetworkEvent
//!                   ┌──────────▼──────────────┐
//!                   │  run_network_dispatch    │ ← serves RangeRequests,
//!                   │  (network_runner)        │   logs gossip events
//!                   └─────────────────────────┘
//!
//!            block_tx (mpsc)
//! producer ────────────────► run_block_broadcaster → NetworkHandle.broadcast_block
//! ```
//!
//! All four tasks share the same `watch::Receiver<bool>` shutdown signal.
//! CTRL+C fires `shutdown_tx.send(true)`. Each task breaks on the next
//! `shutdown.changed()` poll.
//!
//! ## Phase 2 forward note
//!
//! Steps 8–9 are replaced by the Surge/Pulse DAG consensus driver.
//! The `Arc<LemmaDb>`, `Arc<RwLock<Mempool>>`, and `block_tx`/`block_rx`
//! channel seam are preserved — they are the surviving artefacts.

use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

use lemma_core::{address::Address, genesis::GenesisConfig};
use lemma_mempool::pool::Mempool;
use lemma_network::{
    NetworkConfig,
    service::NetworkService,
};
use lemma_node::{
    init_chain, InitOutcome, NodeConfig, ProducerConfig,
    run_block_broadcaster, run_network_dispatch, run_producer,
};
use lemma_storage::db::LemmaDb;

/// Mempool capacity for Phase 1 single-node operation.
///
/// Conservative limit: 10_000 pending transactions is well above single-node
/// throughput. Phase 2 will parameterise this from NodeConfig.
const MEMPOOL_CAPACITY: usize = 10_000;

/// Committed-block channel capacity.
///
/// The broadcaster task drains this channel every loop iteration; backlog
/// beyond this depth means the broadcaster is lagging the producer. For
/// Phase 1 (0.5 s/block), 32 slots gives ~16 s of headroom before
/// `try_send` starts returning errors (logged, non-fatal).
const BLOCK_CHANNEL_CAPACITY: usize = 32;

/// Command-line arguments for `lemma-node`.
#[derive(Debug, Parser)]
#[command(name = "lemma-node", about = "Lemma full node — Phase 1 single-node producer + P2P")]
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

    // ── Step 4: runtime DB handle ─────────────────────────────────────────────
    let db = Arc::new(
        LemmaDb::open(&cfg.data_dir)
            .with_context(|| format!("opening runtime DB at {}", cfg.data_dir.display()))?,
    );

    // ── Step 5: mempool ───────────────────────────────────────────────────────
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

    // ── Step 7: network service ───────────────────────────────────────────────
    // Build NetworkConfig from NodeConfig, constructing it as a testnet-style
    // config (fixed listen address) if an explicit port is given, or using
    // the default (random port) for devnet.
    //
    // Phase 1 node identity: ephemeral ed25519 keypair (regenerated each boot).
    // Persistent node identity (load/save from keystore) is an N7/CLI concern.
    let net_cfg = build_network_config(&cfg);
    net_cfg.validate().context("network config validation")?;

    let net_keypair = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from_public_key(&net_keypair.public());

    let (net_service, net_handle, event_rx) =
        NetworkService::new(net_keypair, &net_cfg)
            .context("building network service")?;

    info!(
        peer_id   = %local_peer_id,
        listen    = %cfg.listen_addr,
        bootstrap = cfg.bootstrap_peers.len(),
        "network service initialised (ephemeral peer identity)"
    );

    // ── Step 8: committed-block channel (producer → broadcaster) ─────────────
    // The producer emits committed blocks here; run_block_broadcaster forwards
    // them to the gossip mesh. This is the surviving seam into Phase 2
    // (DAG consensus driver replaces the timer loop but keeps this channel).
    let (block_tx, block_rx) = mpsc::channel(BLOCK_CHANNEL_CAPACITY);

    // ── Step 9: spawn all tasks, wait for all to exit ─────────────────────────
    let proposer     = Address::zero();
    let producer_cfg = ProducerConfig { block_interval_ms: cfg.block_interval_ms };

    info!(
        block_interval_ms = cfg.block_interval_ms,
        "starting single-node producer (Phase 1)"
    );

    let (net_res, bcast_res, dispatch_res, producer_res) = tokio::join!(
        // Network swarm event loop (lemma-network).
        // Shuts down when all NetworkHandle clones are dropped.
        tokio::spawn(net_service.run()),

        // Block broadcaster: producer → gossip mesh.
        tokio::spawn(run_block_broadcaster(
            net_handle.clone(),
            block_rx,
            shutdown_rx.clone(),
        )),

        // Network event dispatcher: inbound P2P → node state.
        tokio::spawn(run_network_dispatch(
            Arc::clone(&db),
            Arc::clone(&mempool),
            net_handle,          // last clone — drops here on task exit → shuts down net_service
            event_rx,
            shutdown_rx.clone(),
        )),

        // Block producer: timer loop → build → commit → emit on block_tx.
        tokio::spawn(run_producer(
            Arc::clone(&db),
            Arc::clone(&mempool),
            producer_cfg,
            proposer,
            Some(block_tx),
            shutdown_rx,
        )),
    );

    // Propagate JoinError (task panicked) or inner NodeError.
    net_res.context("network service task panicked")?;
    bcast_res.context("block broadcaster task panicked")?;
    dispatch_res.context("network dispatch task panicked")?.context("network dispatch error")?;
    producer_res.context("producer task panicked")?.context("producer error")?;

    info!("lemma-node shutdown complete");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a [`NetworkConfig`] from the node's [`NodeConfig`].
///
/// Applies the node's `listen_addr` and `bootstrap_peers`. All DoS-limit
/// fields use [`NetworkConfig::default`] values (same as a devnet node).
///
/// We call `cfg.parsed_listen_addr()` / `cfg.parsed_bootstrap_peers()` here
/// rather than in the config struct because `NetworkConfig` owns `Vec<Multiaddr>`
/// while `NodeConfig` stores the raw JSON strings (so the JSON config file
/// stays human-readable without embedded libp2p types).
fn build_network_config(cfg: &NodeConfig) -> NetworkConfig {
    NetworkConfig {
        listen_addrs:    vec![cfg.parsed_listen_addr()],
        bootstrap_peers: cfg.parsed_bootstrap_peers(),
        ..NetworkConfig::default()
    }
}
