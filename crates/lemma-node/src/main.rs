//! Lemma full-node binary entry point.
//!
//! ## Boot sequence (Phase 1 N6)
//!
//! ```text
//! 1.  Parse CLI args → load + validate NodeConfig
//! 2.  Parse GenesisConfig from JSON
//! 3.  init_chain (one-time setup, separate LemmaDb handle — consumed + dropped)
//! 4.  Re-open LemmaDb as Arc<LemmaDb> (shared runtime handle)
//! 5.  Create Arc<RwLock<Mempool>>
//! 6.  Wire shutdown signal (watch channel + CTRL+C handler)
//! 7.  Build NetworkConfig from NodeConfig + start NetworkService
//! 8.  Wire committed-block channel (producer → broadcaster)
//! 9.  Create shared write-lock (producer + range-sync consumer)
//! 10. Spawn four tasks and join: network_service, block_broadcaster,
//!     network_dispatch (range-sync consumer), producer
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
//!                   │  run_network_dispatch    │ ← serves RangeRequests
//!                   │  (network_runner)        │   applies synced blocks
//!                   └────────────┬────────────┘   issues RequestRange on gap
//!                           write_lock │
//!            block_tx (mpsc)           │ write_lock
//! producer ────────────────► run_block_broadcaster → NetworkHandle.broadcast_block
//!    │ write_lock                                     (separate task)
//!    └──────────────── same Arc<Mutex<()>> ──────────────────────────────────
//! ```
//!
//! ## Write-lock
//!
//! The producer (`commit_block`) and the range-sync consumer (`apply_synced_block`)
//! share `write_lock: Arc<Mutex<()>>` to serialize `ChainStore::put_block` calls.
//! Per `chain.rs` §Tip race under concurrent writers: without serialization, two
//! concurrent `put_block` callers can clobber the tip metadata.

use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::info;

use lemma_core::{address::Address, genesis::GenesisConfig};
use lemma_mempool::pool::Mempool;
use lemma_network::{service::NetworkService, NetworkConfig};
use lemma_node::{
    init_chain, run_block_broadcaster, run_network_dispatch, run_producer, InitOutcome, NodeConfig,
    ProducerConfig,
};
use lemma_storage::db::LemmaDb;

const MEMPOOL_CAPACITY: usize = 10_000;
const BLOCK_CHANNEL_CAPACITY: usize = 32;

#[derive(Debug, Parser)]
#[command(
    name = "lemma-node",
    about = "Lemma full node — Phase 1 producer + P2P + range-sync"
)]
struct Args {
    #[arg(long, default_value = "config.json")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let cfg = NodeConfig::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;
    cfg.validate().context("config validation")?;

    let genesis_bytes = std::fs::read_to_string(&cfg.genesis_path)
        .with_context(|| format!("reading genesis from {}", cfg.genesis_path.display()))?;
    let genesis: GenesisConfig =
        serde_json::from_str(&genesis_bytes).context("parsing genesis JSON")?;

    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("creating data_dir {}", cfg.data_dir.display()))?;

    match init_chain(
        LemmaDb::open(&cfg.data_dir)
            .with_context(|| format!("opening init DB at {}", cfg.data_dir.display()))?,
        &genesis,
    )
    .context("genesis boot")?
    {
        InitOutcome::Initialized {
            genesis_hash,
            accounts,
        } => {
            info!(genesis_hash = %genesis_hash.to_hex(), accounts, "chain initialised");
        }
        InitOutcome::AlreadyInitialized { height } => {
            info!(height, "chain already initialised — skipping genesis");
        }
    }

    let db = Arc::new(
        LemmaDb::open(&cfg.data_dir)
            .with_context(|| format!("opening runtime DB at {}", cfg.data_dir.display()))?,
    );
    let mempool = Arc::new(RwLock::new(Mempool::new(MEMPOOL_CAPACITY)));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let tx_ctrlc = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
        info!("CTRL+C received — signalling shutdown");
        let _ = tx_ctrlc.send(true);
    });

    // Network service
    let net_cfg = build_network_config(&cfg);
    net_cfg.validate().context("network config validation")?;
    let net_keypair = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from_public_key(&net_keypair.public());
    let (net_service, net_handle, event_rx) =
        NetworkService::new(net_keypair, &net_cfg).context("building network service")?;

    info!(
        peer_id   = %local_peer_id,
        listen    = %cfg.listen_addr,
        bootstrap = cfg.bootstrap_peers.len(),
        "network service initialised (ephemeral peer identity)"
    );

    // Committed-block channel (producer → broadcaster)
    let (block_tx, block_rx) = mpsc::channel(BLOCK_CHANNEL_CAPACITY);

    // Shared write-lock: producer commit + range-sync apply
    let write_lock = Arc::new(Mutex::new(()));

    let proposer = Address::zero();
    let producer_cfg = ProducerConfig {
        block_interval_ms: cfg.block_interval_ms,
    };

    info!(
        block_interval_ms = cfg.block_interval_ms,
        "starting single-node producer (Phase 1)"
    );

    let (net_res, bcast_res, dispatch_res, producer_res) = tokio::join!(
        tokio::spawn(net_service.run()),
        tokio::spawn(run_block_broadcaster(
            net_handle.clone(),
            block_rx,
            shutdown_rx.clone(),
        )),
        tokio::spawn(run_network_dispatch(
            Arc::clone(&db),
            Arc::clone(&mempool),
            net_handle,
            Arc::clone(&write_lock),
            event_rx,
            shutdown_rx.clone(),
        )),
        tokio::spawn(run_producer(
            Arc::clone(&db),
            Arc::clone(&mempool),
            producer_cfg,
            proposer,
            Some(block_tx),
            Arc::clone(&write_lock),
            shutdown_rx,
        )),
    );

    net_res.context("network service task panicked")?;
    bcast_res.context("block broadcaster task panicked")?;
    dispatch_res
        .context("network dispatch task panicked")?
        .context("network dispatch error")?;
    producer_res
        .context("producer task panicked")?
        .context("producer error")?;

    info!("lemma-node shutdown complete");
    Ok(())
}

fn build_network_config(cfg: &NodeConfig) -> NetworkConfig {
    NetworkConfig {
        listen_addrs: vec![cfg.parsed_listen_addr()],
        bootstrap_peers: cfg.parsed_bootstrap_peers(),
        ..NetworkConfig::default()
    }
}
