//! RPC handler modules — one per endpoint group.
//!
//! Each sub-module implements a set of related `lem_*` methods.
//!
//! | Module | Methods |
//! |--------|---------|
//! | [`chain`]  | `lem_blockNumber`, `lem_getBlock`, `lem_getLogs` |
//! | [`state`]  | `lem_getBalance`, `lem_getCode`, `lem_getStorageAt`, `lem_call` |
//! | [`tx`]     | `lem_sendTransaction`, `lem_getTransactionReceipt` |
//! | [`fee`]    | `lem_gasPrice` |
//! | [`lemma`]  | `lem_safetyScore`, `lem_stateAccess` |

pub mod chain;
pub mod fee;
pub mod lemma;
pub mod state;
pub mod tx;
