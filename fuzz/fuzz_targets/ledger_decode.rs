//! Anything that decodes must re-encode to exactly the same bytes.
#![no_main]

use ironwrit_ledger::LedgerEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entry) = LedgerEntry::decode(data) {
        assert_eq!(entry.encode(), data);
    }
});
