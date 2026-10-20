//! The process-wide object cap is set once. Own test binaries (one global
//! each) so the unit tests keep the default.

use scl_core::{
    max_object_size, set_max_object_size, DEFAULT_MAX_OBJECT_SIZE, MAX_MAX_OBJECT_SIZE,
    MIN_MAX_OBJECT_SIZE,
};

#[test]
fn cap_is_set_once_validated_and_then_fixed() {
    // Out-of-range values are refused and leave nothing fixed.
    assert!(set_max_object_size(MIN_MAX_OBJECT_SIZE - 1).is_err());
    assert!(set_max_object_size(MAX_MAX_OBJECT_SIZE + 1).is_err());

    set_max_object_size(2 * MIN_MAX_OBJECT_SIZE).unwrap();
    assert_ne!(2 * MIN_MAX_OBJECT_SIZE, DEFAULT_MAX_OBJECT_SIZE);
    assert_eq!(max_object_size(), 2 * MIN_MAX_OBJECT_SIZE);
    // Same value again is a no-op; a different one is refused.
    set_max_object_size(2 * MIN_MAX_OBJECT_SIZE).unwrap();
    let err = set_max_object_size(MAX_MAX_OBJECT_SIZE).unwrap_err();
    assert!(err.contains("already fixed"), "got {err}");
    assert_eq!(max_object_size(), 2 * MIN_MAX_OBJECT_SIZE);
}
