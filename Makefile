# Lemma workspace gate commands.
#
# WHY THIS EXISTS (read before running cargo by hand):
# cargo uses SEPARATE artifact caches for the `test` profile (`cargo test`),
# the `dev` profile (`cargo build`/`cargo check`), and the clippy driver
# (`cargo clippy`). Interleaving them forces a ~4-minute RocksDB (C++) rebuild
# every time you switch. These targets each pin ONE command shape, so each
# warms its own cache once and then stays fast. ALWAYS use these targets for
# gates — do not mix raw `cargo build --tests` with `cargo test`.
#
# Usage:
#   make check   # the full pre-commit gate: fmt + clippy + test (in order)
#   make test    # workspace tests only        (test profile)
#   make lint    # workspace clippy -D warnings (clippy driver)
#   make fmt     # check formatting             (no compile)
#   make fmt-fix # apply formatting
#   make clean-rocksdb  # reclaim disk from stale librocksdb-sys build dirs

.PHONY: check test lint fmt fmt-fix clean-rocksdb

# Full gate, in the canonical order. Each step is the ONE command for its
# profile; running them in this fixed order keeps each cache warm.
check: fmt lint test

# Tests — `test` profile. Never substitute `cargo build --tests` (dev profile).
test:
	cargo test --workspace

# Lint — clippy driver, warnings are errors (the project gate).
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Format check — no compilation, always fast.
fmt:
	cargo fmt --all -- --check

fmt-fix:
	cargo fmt --all

# Reclaim disk when stale RocksDB build dirs accumulate (fingerprint churn).
# Safe: cargo recompiles librocksdb-sys on next build of a storage-dependent crate.
clean-rocksdb:
	cargo clean -p librocksdb-sys
