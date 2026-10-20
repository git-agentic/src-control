//! The process-wide object cap is set once. Own test binary so the global is
//! not shared with the unit tests (which rely on the default).

use scl_core::{
    max_object_size, set_max_object_size, DEFAULT_MAX_OBJECT_SIZE, MAX_MAX_OBJECT_SIZE,
    MIN_MAX_OBJECT_SIZE,
};

#[test]
fn cap_is_set_once_validated_and_then_fixed() {
    assert_eq!(max_object_size(), DEFAULT_MAX_OBJECT_SIZE);
    // Out-of-range values are refused and leave the default in place.
    assert!(set_max_object_size(MIN_MAX_OBJECT_SIZE - 1).is_err());
    assert!(set_max_object_size(MAX_MAX_OBJECT_SIZE + 1).is_err());
    assert_eq!(max_object_size(), DEFAULT_MAX_OBJECT_SIZE);

    set_max_object_size(2 * MIN_MAX_OBJECT_SIZE).unwrap();
    assert_eq!(max_object_size(), 2 * MIN_MAX_OBJECT_SIZE);
    // Same value again is a no-op; a different one is refused.
    set_max_object_size(2 * MIN_MAX_OBJECT_SIZE).unwrap();
    let err = set_max_object_size(MAX_MAX_OBJECT_SIZE).unwrap_err();
    assert!(err.contains("already fixed"), "got {err}");
    assert_eq!(max_object_size(), 2 * MIN_MAX_OBJECT_SIZE);
}
