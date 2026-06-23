use super::*;

#[test]
fn feature_id_ordering_is_by_inner_value() {
    assert!(FeatureId(0) < FeatureId(1));
    assert!(FeatureId(1) < FeatureId(2));
    assert_eq!(FeatureId(1), FeatureId(1));
}

#[test]
fn feature_id_zero_is_distinct_from_host_abi_v2() {
    assert_ne!(FeatureId(0), FEATURE_HOST_ABI_V2);
}

#[test]
fn feature_host_abi_v2_has_expected_id() {
    assert_eq!(FEATURE_HOST_ABI_V2.0, 1);
}
