//! Fuzz `scl_fuzz::pack_stream` (see fuzz/src/lib.rs for what it reaches).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| scl_fuzz::pack_stream(data));
