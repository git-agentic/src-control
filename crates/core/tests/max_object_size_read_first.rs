//! Reading the cap fixes it: a guard that already ran with the default must
//! not be contradicted by a later `set`.

use scl_core::{
    max_object_size, set_max_object_size, DEFAULT_MAX_OBJECT_SIZE, MIN_MAX_OBJECT_SIZE,
};

#[test]
fn a_read_before_set_fixes_the_default() {
    assert_eq!(max_object_size(), DEFAULT_MAX_OBJECT_SIZE);
    let err = set_max_object_size(MIN_MAX_OBJECT_SIZE).unwrap_err();
    assert!(err.contains("already fixed"), "got {err}");
    // Setting the value already in force is fine.
    set_max_object_size(DEFAULT_MAX_OBJECT_SIZE).unwrap();
    assert_eq!(max_object_size(), DEFAULT_MAX_OBJECT_SIZE);
}
