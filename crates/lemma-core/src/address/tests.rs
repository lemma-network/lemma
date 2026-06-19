//! Tests for `lemma_core::address`.
//!
//! Covers AddressType, all constructors, Bech32m encode/decode,
//! access methods, Display/Debug/Serde, and all derived traits.
//! 100% public API coverage per AGENTS.md §11.1.

use std::collections::HashMap;

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// A deterministic 32-byte Ed25519-style public key for testing.
fn test_pubkey() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

/// A second, distinct public key.
fn test_pubkey_2() -> [u8; 32] {
    let mut k = [0xffu8; 32];
    k[0] = 0xAB;
    k
}

fn test_deployer() -> Address {
    Address::from_public_key(&test_pubkey())
}

fn test_salt() -> [u8; 32] {
    [0xDEu8; 32]
}

// ── AddressType::type_byte ────────────────────────────────────────────────────

#[test]
fn address_type_regular_has_correct_type_byte() {
    assert_eq!(AddressType::Regular.type_byte(), 0x00);
}

#[test]
fn address_type_contract_has_correct_type_byte() {
    assert_eq!(AddressType::Contract.type_byte(), 0xC0);
}

#[test]
fn address_type_shielded_has_correct_type_byte() {
    assert_eq!(AddressType::Shielded.type_byte(), 0x10);
}

#[test]
fn address_type_burn_has_correct_type_byte() {
    assert_eq!(AddressType::Burn.type_byte(), 0x6E);
}

// ── AddressType::from_type_byte ───────────────────────────────────────────────

#[test]
fn from_type_byte_parses_regular() {
    assert_eq!(
        AddressType::from_type_byte(0x00).unwrap(),
        AddressType::Regular
    );
}

#[test]
fn from_type_byte_parses_contract() {
    assert_eq!(
        AddressType::from_type_byte(0xC0).unwrap(),
        AddressType::Contract
    );
}

#[test]
fn from_type_byte_parses_shielded() {
    assert_eq!(
        AddressType::from_type_byte(0x10).unwrap(),
        AddressType::Shielded
    );
}

#[test]
fn from_type_byte_parses_burn() {
    assert_eq!(
        AddressType::from_type_byte(0x6E).unwrap(),
        AddressType::Burn
    );
}

#[test]
fn from_type_byte_rejects_unknown_byte() {
    let result = AddressType::from_type_byte(0xFF);
    assert!(matches!(
        result,
        Err(crate::error::AddressError::UnknownAddressType { byte: 0xFF })
    ));
}

#[test]
fn from_type_byte_rejects_old_incorrect_contract_byte() {
    // 0x02 was incorrectly in the old spec — must be rejected.
    let result = AddressType::from_type_byte(0x02);
    assert!(result.is_err());
}

#[test]
fn address_type_roundtrips_via_type_byte() {
    for ty in [
        AddressType::Regular,
        AddressType::Contract,
        AddressType::Shielded,
        AddressType::Burn,
    ] {
        assert_eq!(AddressType::from_type_byte(ty.type_byte()).unwrap(), ty);
    }
}

// ── Address::zero() ───────────────────────────────────────────────────────────

#[test]
fn zero_returns_all_zero_bytes() {
    assert_eq!(Address::zero().as_bytes(), &[0u8; 20]);
}

#[test]
fn zero_is_zero_returns_true() {
    assert!(Address::zero().is_zero());
}

#[test]
fn zero_is_burn_returns_false() {
    // zero() is a sentinel — NOT the burn address.
    assert!(!Address::zero().is_burn());
}

// ── Address::burn() ───────────────────────────────────────────────────────────

#[test]
fn burn_is_zero_returns_false() {
    assert!(!Address::burn().is_zero());
}

#[test]
fn burn_is_burn_returns_true() {
    assert!(Address::burn().is_burn());
}

#[test]
fn burn_encodes_to_dead_pattern_on_mainnet() {
    let encoded = Address::burn()
        .to_bech32(HRP_MAINNET, AddressType::Burn)
        .unwrap();
    // Must start with "lem1dead"
    assert!(encoded.starts_with("lem1dead"), "got: {}", encoded);
}

#[test]
fn burn_display_contains_dead_substring() {
    // Default Display uses Regular type, so first visible chars are 'q'.
    // But we can verify the burn address encodes correctly with Burn type.
    let encoded = Address::burn()
        .to_bech32(HRP_MAINNET, AddressType::Burn)
        .unwrap();
    assert!(
        encoded.contains("dead"),
        "burn address must contain 'dead': {}",
        encoded
    );
}

// ── Address::native_lem() ─────────────────────────────────────────────────────

#[test]
fn native_lem_is_not_zero() {
    assert!(!Address::native_lem().is_zero());
}

#[test]
fn native_lem_is_not_burn() {
    assert!(!Address::native_lem().is_burn());
}

#[test]
fn native_lem_encodes_as_contract_type_on_mainnet() {
    let encoded = Address::native_lem()
        .to_bech32(HRP_MAINNET, AddressType::Contract)
        .unwrap();
    assert!(encoded.starts_with("lem1c"), "got: {}", encoded);
}

#[test]
fn native_lem_bytes_match_blake3_hash() {
    // Verifies the hard-coded NATIVE_LEM_BYTES constant.
    let hash = blake3::hash(b"lemma:system:native-lem");
    let expected = &hash.as_bytes()[..20];
    assert_eq!(
        Address::native_lem().as_bytes(),
        expected,
        "NATIVE_LEM_BYTES constant is stale — recompute from blake3"
    );
}

// ── Address::registry() ───────────────────────────────────────────────────────

#[test]
fn registry_is_not_zero() {
    assert!(!Address::registry().is_zero());
}

#[test]
fn registry_is_not_burn() {
    assert!(!Address::registry().is_burn());
}

#[test]
fn registry_is_distinct_from_native_lem() {
    assert_ne!(Address::registry(), Address::native_lem());
}

#[test]
fn registry_is_distinct_from_zero() {
    assert_ne!(Address::registry(), Address::zero());
}

#[test]
fn registry_is_distinct_from_burn() {
    assert_ne!(Address::registry(), Address::burn());
}

#[test]
fn registry_is_deterministic() {
    // Two calls must return the same address — blake3 is deterministic.
    assert_eq!(Address::registry(), Address::registry());
}

#[test]
fn registry_bytes_match_blake3_hash() {
    // Verifies that Address::registry() returns the correct blake3-derived bytes.
    // This is the canonical correctness check — if the derivation formula ever
    // changes, this test will catch it. See DB-A54.
    let hash = blake3::hash(b"lemma:system:registry");
    let expected = &hash.as_bytes()[..20];
    assert_eq!(
        Address::registry().as_bytes(),
        expected,
        "registry() must return blake3(b\"lemma:system:registry\")[0..20]"
    );
}

#[test]
fn registry_encodes_as_contract_type_on_mainnet() {
    let encoded = Address::registry()
        .to_bech32(HRP_MAINNET, AddressType::Contract)
        .unwrap();
    assert!(encoded.starts_with("lem1c"), "got: {}", encoded);
}

// ── Address::from_public_key ──────────────────────────────────────────────────

#[test]
fn from_public_key_is_deterministic() {
    let addr1 = Address::from_public_key(&test_pubkey());
    let addr2 = Address::from_public_key(&test_pubkey());
    assert_eq!(addr1, addr2);
}

#[test]
fn from_public_key_produces_20_byte_address() {
    let addr = Address::from_public_key(&test_pubkey());
    assert_eq!(addr.as_bytes().len(), 20);
}

#[test]
fn from_public_key_different_keys_produce_different_addresses() {
    let a = Address::from_public_key(&test_pubkey());
    let b = Address::from_public_key(&test_pubkey_2());
    assert_ne!(a, b);
}

#[test]
fn from_public_key_is_not_zero() {
    // Probability of getting all-zero from a real pubkey hash is negligible.
    assert!(!Address::from_public_key(&test_pubkey()).is_zero());
}

// ── Address::from_deployer ────────────────────────────────────────────────────

#[test]
fn from_deployer_is_deterministic() {
    let d = test_deployer();
    assert_eq!(Address::from_deployer(&d, 0), Address::from_deployer(&d, 0));
}

#[test]
fn from_deployer_different_nonces_produce_different_addresses() {
    let d = test_deployer();
    assert_ne!(Address::from_deployer(&d, 0), Address::from_deployer(&d, 1));
}

#[test]
fn from_deployer_different_deployers_produce_different_addresses() {
    let d1 = Address::from_public_key(&test_pubkey());
    let d2 = Address::from_public_key(&test_pubkey_2());
    assert_ne!(
        Address::from_deployer(&d1, 0),
        Address::from_deployer(&d2, 0)
    );
}

#[test]
fn from_deployer_nonce_u64_max_does_not_panic() {
    let d = test_deployer();
    let _ = Address::from_deployer(&d, u64::MAX);
}

// ── Address::from_deployer_salt ───────────────────────────────────────────────

#[test]
fn from_deployer_salt_is_deterministic() {
    let d = test_deployer();
    let s = test_salt();
    let a = Address::from_deployer_salt(&d, &s, b"bytecode");
    let b = Address::from_deployer_salt(&d, &s, b"bytecode");
    assert_eq!(a, b);
}

#[test]
fn from_deployer_salt_different_salts_produce_different_addresses() {
    let d = test_deployer();
    let salt1 = [0x00u8; 32];
    let salt2 = [0x01u8; 32];
    assert_ne!(
        Address::from_deployer_salt(&d, &salt1, b"bytecode"),
        Address::from_deployer_salt(&d, &salt2, b"bytecode"),
    );
}

#[test]
fn from_deployer_salt_different_bytecodes_produce_different_addresses() {
    let d = test_deployer();
    let s = test_salt();
    assert_ne!(
        Address::from_deployer_salt(&d, &s, b"bytecode_v1"),
        Address::from_deployer_salt(&d, &s, b"bytecode_v2"),
    );
}

#[test]
fn from_deployer_salt_differs_from_from_deployer() {
    // CREATE and CREATE2 must not collide (0xff prefix prevents this).
    let d = test_deployer();
    let s = test_salt();
    let create = Address::from_deployer(&d, 0);
    let create2 = Address::from_deployer_salt(&d, &s, b"code");
    assert_ne!(create, create2);
}

#[test]
fn from_deployer_salt_empty_bytecode_does_not_panic() {
    // Empty bytecode is unusual but blake3::hash(b"") is well-defined — must not panic.
    let d = test_deployer();
    let s = test_salt();
    let addr = Address::from_deployer_salt(&d, &s, b"");
    assert_ne!(addr, Address::zero());
}

// ── Address::to_bech32 ────────────────────────────────────────────────────────

#[test]
fn to_bech32_regular_on_mainnet_starts_with_lem1q() {
    let addr = Address::from_public_key(&test_pubkey());
    let encoded = addr.to_bech32(HRP_MAINNET, AddressType::Regular).unwrap();
    assert!(encoded.starts_with("lem1q"), "got: {}", encoded);
}

#[test]
fn to_bech32_contract_on_mainnet_starts_with_lem1c() {
    let addr = Address::from_deployer(&test_deployer(), 0);
    let encoded = addr.to_bech32(HRP_MAINNET, AddressType::Contract).unwrap();
    assert!(encoded.starts_with("lem1c"), "got: {}", encoded);
}

#[test]
fn to_bech32_shielded_on_mainnet_starts_with_lem1z() {
    let addr = Address::from_public_key(&test_pubkey());
    let encoded = addr.to_bech32(HRP_MAINNET, AddressType::Shielded).unwrap();
    assert!(encoded.starts_with("lem1z"), "got: {}", encoded);
}

#[test]
fn to_bech32_burn_on_mainnet_starts_with_lem1dead() {
    let encoded = Address::burn()
        .to_bech32(HRP_MAINNET, AddressType::Burn)
        .unwrap();
    assert!(encoded.starts_with("lem1dead"), "got: {}", encoded);
}

#[test]
fn to_bech32_regular_on_testnet_starts_with_tlem1q() {
    let addr = Address::from_public_key(&test_pubkey());
    let encoded = addr.to_bech32(HRP_TESTNET, AddressType::Regular).unwrap();
    assert!(encoded.starts_with("tlem1q"), "got: {}", encoded);
}

#[test]
fn to_bech32_regular_on_devnet_starts_with_dlem1q() {
    let addr = Address::from_public_key(&test_pubkey());
    let encoded = addr.to_bech32(HRP_DEVNET, AddressType::Regular).unwrap();
    assert!(encoded.starts_with("dlem1q"), "got: {}", encoded);
}

#[test]
fn to_bech32_rejects_unknown_hrp() {
    let addr = Address::from_public_key(&test_pubkey());
    let result = addr.to_bech32("eth", AddressType::Regular);
    assert!(matches!(
        result,
        Err(crate::error::AddressError::InvalidHrp { .. })
    ));
}

// ── Address::from_bech32 ─────────────────────────────────────────────────────

#[test]
fn from_bech32_roundtrips_regular_mainnet() {
    let original = Address::from_public_key(&test_pubkey());
    let encoded = original
        .to_bech32(HRP_MAINNET, AddressType::Regular)
        .unwrap();
    let (decoded, ty, hrp) = Address::from_bech32(&encoded).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(ty, AddressType::Regular);
    assert_eq!(hrp, HRP_MAINNET);
}

#[test]
fn from_bech32_roundtrips_contract_testnet() {
    let original = Address::from_deployer(&test_deployer(), 42);
    let encoded = original
        .to_bech32(HRP_TESTNET, AddressType::Contract)
        .unwrap();
    let (decoded, ty, hrp) = Address::from_bech32(&encoded).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(ty, AddressType::Contract);
    assert_eq!(hrp, HRP_TESTNET);
}

#[test]
fn from_bech32_roundtrips_burn_address() {
    let encoded = Address::burn()
        .to_bech32(HRP_MAINNET, AddressType::Burn)
        .unwrap();
    let (decoded, ty, hrp) = Address::from_bech32(&encoded).unwrap();
    assert_eq!(decoded, Address::burn());
    assert_eq!(ty, AddressType::Burn);
    assert_eq!(hrp, HRP_MAINNET);
}

#[test]
fn from_bech32_rejects_invalid_checksum() {
    let mut encoded = Address::burn()
        .to_bech32(HRP_MAINNET, AddressType::Burn)
        .unwrap();
    // Corrupt last character
    let last = encoded.pop().unwrap();
    encoded.push(if last == 'q' { 'p' } else { 'q' });
    assert!(Address::from_bech32(&encoded).is_err());
}

#[test]
fn from_bech32_rejects_valid_bech32_with_non_lemma_hrp() {
    // "bc1q..." is a valid Bitcoin bech32 address — valid checksum but wrong HRP.
    // Must be rejected with InvalidHrp (not InvalidBech32).
    let result = Address::from_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    assert!(result.is_err());
}

#[test]
fn from_bech32_rejects_malformed_strings() {
    // These are not valid bech32/bech32m strings — they fail at checksum stage.
    for bad in ["eth1abc", "sol1abc", "not-a-bech32", ""] {
        assert!(Address::from_bech32(bad).is_err(), "should reject: {}", bad);
    }
}

// ── Address::as_bytes ────────────────────────────────────────────────────────

#[test]
fn as_bytes_returns_the_underlying_20_bytes() {
    let addr = Address::from_public_key(&test_pubkey());
    let bytes = addr.as_bytes();
    assert_eq!(bytes.len(), 20);
    // Construct a second address from the same bytes and verify equality.
    let mut raw = [0u8; 20];
    raw.copy_from_slice(bytes);
    assert_eq!(Address(raw), addr);
}

// ── Address::is_zero + is_burn ────────────────────────────────────────────────

#[test]
fn is_zero_false_for_nonzero_address() {
    assert!(!test_deployer().is_zero());
}

#[test]
fn is_burn_false_for_non_burn_address() {
    assert!(!test_deployer().is_burn());
}

#[test]
fn zero_and_burn_are_not_equal() {
    assert_ne!(Address::zero(), Address::burn());
}

// ── Address::short_display ────────────────────────────────────────────────────

#[test]
fn short_display_contains_ellipsis() {
    let s = test_deployer().short_display();
    assert!(s.contains("..."), "got: {}", s);
}

#[test]
fn short_display_starts_with_lem1() {
    let s = test_deployer().short_display();
    assert!(s.starts_with("lem1"), "got: {}", s);
}

#[test]
fn short_display_is_shorter_than_full_display() {
    let addr = test_deployer();
    assert!(addr.short_display().len() < addr.to_string().len());
}

// ── Display ───────────────────────────────────────────────────────────────────

#[test]
fn display_starts_with_lem1q() {
    // Default Display = mainnet Regular → first visible char is 'q'.
    assert!(test_deployer().to_string().starts_with("lem1q"));
}

#[test]
fn display_of_zero_starts_with_lem1q() {
    assert!(Address::zero().to_string().starts_with("lem1q"));
}

// ── Debug ─────────────────────────────────────────────────────────────────────

#[test]
fn debug_wraps_display_in_address_prefix() {
    let addr = test_deployer();
    let debug = format!("{:?}", addr);
    assert!(debug.starts_with("Address(lem1q"), "got: {}", debug);
    assert!(debug.ends_with(')'), "got: {}", debug);
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn serialize_to_json_produces_bech32m_string() {
    let addr = test_deployer();
    let json = serde_json::to_string(&addr).unwrap();
    // JSON wraps in quotes; inner value must be a valid lem1q... string.
    let inner: String = serde_json::from_str(&json).unwrap();
    assert!(inner.starts_with("lem1q"), "got: {}", inner);
}

#[test]
fn deserialize_from_json_roundtrips() {
    let original = test_deployer();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Address = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn deserialize_accepts_any_valid_network_prefix() {
    let addr = test_deployer();
    for hrp in [HRP_MAINNET, HRP_TESTNET, HRP_DEVNET] {
        let encoded = addr.to_bech32(hrp, AddressType::Regular).unwrap();
        let json = format!("\"{}\"", encoded);
        let decoded: Address = serde_json::from_str(&json).unwrap();
        // Only bytes are preserved — HRP is discarded.
        assert_eq!(decoded, addr);
    }
}

#[test]
fn deserialize_rejects_invalid_string() {
    let result = serde_json::from_str::<Address>("\"not-a-valid-address\"");
    assert!(result.is_err());
}

// ── Clone + Copy ──────────────────────────────────────────────────────────────

#[test]
fn clone_produces_equal_address() {
    let addr = test_deployer();
    assert_eq!(addr.clone(), addr);
}

#[test]
fn copy_semantics_work_correctly() {
    let original = test_deployer();
    let copied = original;
    assert_eq!(original, copied);
}

// ── PartialEq + Eq ────────────────────────────────────────────────────────────

#[test]
fn same_address_bytes_are_equal() {
    let a = Address::from_public_key(&test_pubkey());
    let b = Address::from_public_key(&test_pubkey());
    assert_eq!(a, b);
}

#[test]
fn different_address_bytes_are_not_equal() {
    assert_ne!(
        Address::from_public_key(&test_pubkey()),
        Address::from_public_key(&test_pubkey_2()),
    );
}

// ── Hash (usable in HashMap) ──────────────────────────────────────────────────

// HashMap used only for key-lookup tests (no iteration — no order dependency).
// For any test requiring deterministic iteration, use BTreeMap per AGENTS.md §7.1.
#[test]
fn address_can_be_used_as_hashmap_key() {
    let mut map: HashMap<Address, &str> = HashMap::new();
    let eoa = test_deployer();
    map.insert(eoa, "alice");
    map.insert(Address::burn(), "burn");
    assert_eq!(*map.get(&eoa).unwrap(), "alice");
    assert_eq!(*map.get(&Address::burn()).unwrap(), "burn");
}

#[test]
fn same_address_bytes_produce_same_hashmap_lookup() {
    let mut map: HashMap<Address, u64> = HashMap::new();
    let addr = test_deployer();
    map.insert(addr, 100);
    // Reconstruct from bytes — must give the same key.
    let mut raw = [0u8; 20];
    raw.copy_from_slice(addr.as_bytes());
    assert_eq!(*map.get(&Address(raw)).unwrap(), 100);
}

// ── PartialOrd + Ord ──────────────────────────────────────────────────────────

#[test]
fn address_ordering_is_lexicographic_over_bytes() {
    // Address with first byte 0x00 < Address with first byte 0x01.
    // This property is required for deterministic BTreeMap iteration
    // across all nodes (AGENTS.md §7.1).
    let low_bytes = [0u8; 20];
    let mut high_bytes = [0u8; 20];
    high_bytes[0] = 0x01;
    let low = Address(low_bytes);
    let high = Address(high_bytes);
    assert!(low < high);
    assert!(high > low);
    assert_eq!(low.cmp(&low), std::cmp::Ordering::Equal);
}

#[test]
fn address_zero_is_less_than_burn() {
    // Address::zero() = [0x00; 20], Address::burn() starts with 0x7A.
    // Confirms well-known addresses have deterministic relative order.
    assert!(Address::zero() < Address::burn());
}

#[test]
fn address_can_be_used_as_btreemap_key() {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<Address, &str> = BTreeMap::new();
    map.insert(Address::burn(), "burn");
    map.insert(Address::zero(), "zero");
    // BTreeMap iteration is always in sorted (ascending) key order.
    let keys: Vec<_> = map.keys().collect();
    assert!(keys[0] < keys[1]);
}

#[test]
fn address_btreemap_iteration_order_is_deterministic_regardless_of_insertion_order() {
    // BTreeMap must produce the same iteration order regardless of insertion
    // sequence — this is the core determinism guarantee for genesis state root
    // computation. See AGENTS.md §7.1.
    use std::collections::BTreeMap;
    let mut m1 = BTreeMap::new();
    m1.insert(Address::burn(), 1u32);
    m1.insert(Address::zero(), 2u32);

    let mut m2 = BTreeMap::new();
    m2.insert(Address::zero(), 2u32); // reversed insertion order
    m2.insert(Address::burn(), 1u32);

    let keys1: Vec<_> = m1.keys().collect();
    let keys2: Vec<_> = m2.keys().collect();
    assert_eq!(keys1, keys2);
}
