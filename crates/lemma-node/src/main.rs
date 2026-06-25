//! Lemma full-node binary entry point.
//!
//! ## Boot sequence (Phase 2 — DAG consensus driver + batch dissemination)
//!
//! ```text
//! 1.  Parse CLI args → load + validate NodeConfig
//! 2.  Parse GenesisConfig from JSON
//! 3.  init_chain (one-time setup, separate LemmaDb handle — consumed + dropped)
//! 4.  Re-open LemmaDb as Arc<LemmaDb> (shared runtime handle)
//! 5.  Create Arc<RwLock<Mempool>>
//! 6.  Create BatchStore (Arc<RwLock<HashMap<Hash, Batch>>>) — shared between
//!     dag_driver (writer: own batches) and network_dispatch (writer: peer batches)
//! 7.  Wire shutdown signal (watch channel + CTRL+C handler)
//! 8.  Build NetworkConfig from NodeConfig + start NetworkService
//! 9.  Wire committed-block channel (dag_driver → broadcaster)
//! 10. Wire dag_block channel (dag_driver → broadcaster for DAG gossip)
//! 11. Wire batch channel (dag_driver → broadcaster for batch gossip, C·Step 14)
//! 12. Wire incoming_dag_block channel (network_dispatch → dag_driver, D·15b-1)
//! 13. Create shared write-lock (dag_driver + range-sync consumer)
//! 14. Build ValidatorSet from genesis config (single-validator, Phase 2)
//! 15. Spawn six tasks and join: network_service, block_broadcaster,
//!     dag_block_broadcaster, batch_broadcaster, network_dispatch, dag_driver
//! ```
//!
//! ## Task topology (Phase 2 + C·Step 14 + D·15b-1)
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
//!                   │  + BatchReceived → pin   │   pins inbound batches
//!                   │  + DagProposal → verify  │   verifies + forwards DagBlocks
//!                   └────────────┬────────────┘
//!                           write_lock │  incoming_dag_block (mpsc)
//!         block_tx (mpsc)             │ write_lock
//! dag_driver ──────────────► run_block_broadcaster → broadcast_block
//!    │ dag_block_tx                                   (separate task)
//!    ├─────────────────────► run_dag_block_broadcaster → broadcast_dag_proposal
//!    │ batch_tx                                        (separate task)
//!    └─────────────────────► run_batch_broadcaster → broadcast_batch
//!    ▲                                                 (separate task)
//!    │ incoming_dag_block_rx
//!    └──────────────────────── run_network_dispatch (peer DagBlocks, D·15b-1)
//!              ▲
//!     BatchStore (shared with network_dispatch for inbound batch pinning)
//! ```
//!
//! ## Write-lock
//!
//! The dag_driver (`commit_block`) and the range-sync consumer (`apply_synced_block`)
//! share `write_lock: Arc<Mutex<()>>` to serialize `ChainStore::put_block` calls.
//! Per `chain.rs` §Tip race under concurrent writers: without serialization, two
//! concurrent `put_block` callers can clobber the tip metadata.

use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::info;

use lemma_consensus::dag::block::DagBlock;
use lemma_core::{
    address::Address,
    amount::Amount,
    genesis::GenesisConfig,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use lemma_crypto::KeyPair;
use lemma_mempool::pool::Mempool;
use lemma_network::{service::NetworkHandle, service::NetworkService, NetworkConfig};
use lemma_node::{
    dag_driver::DagConfig, init_chain, new_batch_store, run_block_broadcaster,
    run_commit_ack_broadcaster, run_dag_driver, run_network_dispatch, InitOutcome, NodeConfig,
};
use lemma_storage::db::LemmaDb;

const MEMPOOL_CAPACITY: usize = 10_000;
const BLOCK_CHANNEL_CAPACITY: usize = 32;
/// Capacity for the raw DagBlock bytes channel (dag_driver → broadcaster).
const DAG_BLOCK_CHANNEL_CAPACITY: usize = 256;
/// Capacity for the raw Batch bytes channel (dag_driver → broadcaster, C·Step 14).
const BATCH_CHANNEL_CAPACITY: usize = 256;
/// Capacity for the incoming DagBlock channel (network_dispatch → dag_driver, D·15b-1).
const INCOMING_DAG_BLOCK_CHANNEL_CAPACITY: usize = 256;

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

    // BatchStore: shared between dag_driver (pins own batches) and
    // network_dispatch (pins batches received from peers via C·Step 14).
    let batch_store = new_batch_store();

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

    // Validator keypair for signing DagBlocks (D·15a — replaces Signature::Unsigned).
    // Phase 2: ephemeral keypair generated at startup (same session = same identity).
    // Phase 3+: load from a persisted keystore (lemma-cli wallet).
    let validator_keypair = Arc::new(KeyPair::generate().context("generating validator keypair")?);
    let proposer = *validator_keypair.address();

    // Read the current chain epoch from the tip block (set by genesis boot → epoch 0).
    // Using the chain's epoch ensures the DAG driver and the chain header are consistent.
    // Phase 3 will load the real validator set from the committed epoch state.
    let chain_epoch = {
        let chain = lemma_storage::ChainStore::new(&db);
        chain
            .tip()
            .ok()
            .flatten()
            .and_then(|(h, _)| chain.get_block_by_height(h).ok().flatten())
            .map(|b| b.header.epoch)
            .unwrap_or(0) // fallback: genesis epoch = 0
    };

    // Build a single-validator ValidatorSet at the current chain epoch.
    // Phase 2 (single-node): the only member is the local proposer.
    // Phase 3 (multi-validator): load the current epoch's ValidatorSet from the chain.
    let validator_set = build_single_node_vset(proposer, &genesis, chain_epoch);

    let dag_cfg = DagConfig {
        epoch: chain_epoch,
        proposer,
        validator_set: validator_set.clone(),
    };

    // DAG block gossip channel: raw JSON-encoded DagBlock bytes.
    let (dag_block_tx, dag_block_rx) = mpsc::channel::<Vec<u8>>(DAG_BLOCK_CHANNEL_CAPACITY);

    // Batch gossip channel: raw JSON-encoded Batch bytes (C·Step 14).
    let (batch_tx, batch_rx) = mpsc::channel::<Vec<u8>>(BATCH_CHANNEL_CAPACITY);

    // Incoming DagBlock channel: (DagBlock, sig_ok) from network_dispatch → dag_driver (D·15b-1).
    // network_dispatch decodes + sig-verifies peer DagBlocks and forwards them here.
    let (incoming_dag_block_tx, incoming_dag_block_rx) =
        mpsc::channel::<(DagBlock, bool)>(INCOMING_DAG_BLOCK_CHANNEL_CAPACITY);

    // Commit-ack gossip channels (P4·Step 9 — multi-signer QuorumCert).
    //
    // `commit_ack_tx`: dag_driver → network_runner → gossip mesh (own ack bytes).
    // `incoming_commit_ack_tx`: network_runner → dag_driver (peer ack + sig_ok).
    //
    // Capacity: 64 is generous — one ack per validator per block; a 100-validator
    // committee produces at most 100 acks per block, well within 64 per iteration.
    const COMMIT_ACK_CHANNEL_CAPACITY: usize = 64;
    let (commit_ack_tx, commit_ack_rx) = mpsc::channel::<Vec<u8>>(COMMIT_ACK_CHANNEL_CAPACITY);
    let (incoming_commit_ack_tx, incoming_commit_ack_rx) =
        mpsc::channel::<(lemma_consensus::CommitAckPayload, bool)>(COMMIT_ACK_CHANNEL_CAPACITY);

    info!(
        epoch    = dag_cfg.epoch,
        proposer = %dag_cfg.proposer,
        "starting DAG consensus driver (Phase 2 — single-node Surge loop)"
    );

    let net_handle_dag = net_handle.clone();
    let net_handle_batch = net_handle.clone();
    let net_handle_commit_ack = net_handle.clone();

    let (
        net_res,
        bcast_res,
        dag_bcast_res,
        batch_bcast_res,
        commit_ack_bcast_res,
        dispatch_res,
        dag_res,
    ) = tokio::join!(
        tokio::spawn(net_service.run()),
        tokio::spawn(run_block_broadcaster(
            net_handle.clone(),
            block_rx,
            shutdown_rx.clone(),
        )),
        tokio::spawn(run_dag_block_broadcaster(
            net_handle_dag,
            dag_block_rx,
            shutdown_rx.clone(),
        )),
        tokio::spawn(run_batch_broadcaster(
            net_handle_batch,
            batch_rx,
            shutdown_rx.clone(),
        )),
        // Commit-ack broadcaster: forwards own ack bytes to the gossip mesh
        // (lemma/commit-ack/1). Same pattern as run_batch_broadcaster (P4·Step 9).
        tokio::spawn(run_commit_ack_broadcaster(
            net_handle_commit_ack,
            commit_ack_rx,
            shutdown_rx.clone(),
        )),
        tokio::spawn(run_network_dispatch(
            Arc::clone(&db),
            Arc::clone(&mempool),
            Arc::clone(&batch_store),
            net_handle,
            Arc::clone(&write_lock),
            event_rx,
            shutdown_rx.clone(),
            validator_set,
            Some(incoming_dag_block_tx),
            Some(incoming_commit_ack_tx),
        )),
        tokio::spawn(run_dag_driver(
            Arc::clone(&db),
            Arc::clone(&mempool),
            dag_cfg,
            Arc::clone(&validator_keypair),
            batch_store,
            Some(block_tx),
            Some(dag_block_tx),
            Some(batch_tx),
            Some(commit_ack_tx),
            Arc::clone(&write_lock),
            shutdown_rx,
            Some(incoming_dag_block_rx),
            Some(incoming_commit_ack_rx),
        )),
    );

    net_res.context("network service task panicked")?;
    bcast_res.context("block broadcaster task panicked")?;
    dag_bcast_res.context("dag block broadcaster task panicked")?;
    batch_bcast_res.context("batch broadcaster task panicked")?;
    commit_ack_bcast_res.context("commit-ack broadcaster task panicked")?;
    dispatch_res
        .context("network dispatch task panicked")?
        .context("network dispatch error")?;
    dag_res
        .context("dag driver task panicked")?
        .context("dag driver error")?;

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

/// Build a single-validator `ValidatorSet` at the given `epoch`.
///
/// Phase 2 (single-node): constructs a committee of 1 — the local proposer —
/// with enough voting power to trivially satisfy all 2f+1 quorum checks.
/// Phase 3 (multi-validator): load the `ValidatorSet` from the committed epoch
/// state instead of constructing it here.
///
/// If `proposer` is not in `genesis_validators`, falls back to 1_000_000 Drop
/// power and logs a warning so misconfiguration is visible.
fn build_single_node_vset(proposer: Address, genesis: &GenesisConfig, epoch: u64) -> ValidatorSet {
    use std::collections::BTreeMap;

    let genesis_entry = genesis.genesis_validators.get(&proposer);

    // Warn if the proposer is not in genesis_validators (silent fallback otherwise).
    if !genesis.genesis_validators.is_empty() && genesis_entry.is_none() {
        tracing::warn!(
            proposer = %proposer,
            "proposer not found in genesis_validators — using 1_000_000 Drop fallback. \
             Configured genesis validators are NOT used (single-node sentinel)."
        );
    }

    let power_drop: u128 = genesis_entry
        .and_then(|v| v.voting_power().ok())
        .map(|vp| vp.0.as_drop())
        .unwrap_or(1_000_000);

    let consensus_pubkey = genesis_entry
        .map(|v| v.consensus_pubkey.clone())
        .unwrap_or_else(|| ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32]));

    let power = VotingPower(Amount::from_drop(power_drop));
    let mut members = BTreeMap::new();
    members.insert(
        proposer,
        Member {
            consensus_pubkey,
            power,
        },
    );

    ValidatorSet {
        epoch,
        members,
        total_power: Amount::from_drop(power_drop),
    }
}

/// Broadcast raw DagBlock bytes to the gossip mesh (lemma/dag/1 topic).
///
/// Drains `dag_block_rx` and calls `NetworkHandle::broadcast_dag_proposal`.
/// Phase 2 (single-node): the broadcast will fail with "no peers subscribed"
/// (non-fatal) since there are no peers. Phase 3 will connect validator peers.
async fn run_dag_block_broadcaster(
    net_handle: NetworkHandle,
    mut dag_block_rx: mpsc::Receiver<Vec<u8>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            Some(bytes) = dag_block_rx.recv() => {
                if let Err(e) = net_handle.broadcast_dag_proposal(bytes).await {
                    tracing::debug!(error = %e, "dag block broadcast failed (non-fatal)");
                }
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("dag_block_broadcaster: shutdown signal — stopping");
                    break;
                }
            }
        }
    }
}

/// Broadcast raw Batch bytes to the gossip mesh (lemma/batch/1 topic, C·Step 14).
///
/// Drains `batch_rx` and calls `NetworkHandle::broadcast_batch`.
/// Must fire BEFORE the `DagBlock` that references the batch is broadcast —
/// peers need to pin the batch before commit-time resolution.
/// Phase 2 (single-node): broadcast fails with "no peers subscribed" (non-fatal).
async fn run_batch_broadcaster(
    net_handle: NetworkHandle,
    mut batch_rx: mpsc::Receiver<Vec<u8>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            Some(bytes) = batch_rx.recv() => {
                if let Err(e) = net_handle.broadcast_batch(bytes).await {
                    tracing::debug!(error = %e, "batch broadcast failed (non-fatal)");
                }
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("batch_broadcaster: shutdown signal — stopping");
                    break;
                }
            }
        }
    }
}
