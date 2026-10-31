//! Stable-toolchain versions of the ledger fuzz targets in `fuzz/`.
//! Raise PROPTEST_CASES for a longer run.

use ironwrit_ledger::merkle;
use ironwrit_ledger::{Decision, LedgerEntry};
use proptest::prelude::*;

fn entry() -> impl Strategy<Value = LedgerEntry> {
    let decision = prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Deny),
        Just(Decision::Completed)
    ];
    (
        1u64..1000,
        any::<u64>(),
        ".{0,12}",
        ".{0,12}",
        any::<[u8; 32]>(),
        decision,
        ".{0,40}",
        any::<[u8; 32]>(),
    )
        .prop_map(
            |(seq, ts, token_id, tool, args_hash, decision, reason, result)| {
                let completed = decision == Decision::Completed;
                LedgerEntry {
                    seq,
                    ts,
                    token_id,
                    tool,
                    args_hash,
                    decision,
                    reason,
                    result_hash: completed.then_some(result),
                    call_seq: completed.then_some(seq - 1),
                }
            },
        )
}

/// `PROPTEST_CASES` overrides the default, for long runs.
fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(4096)))]

    /// Anything that decodes must re-encode to the same bytes, so one entry
    /// has exactly one encoding (and one leaf hash).
    #[test]
    fn arbitrary_bytes_decode_strictly(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(entry) = LedgerEntry::decode(&bytes) {
            prop_assert_eq!(entry.encode(), bytes);
        }
    }

    #[test]
    fn mutated_encodings_decode_strictly(
        entry in entry(),
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut bytes = entry.encode();
        prop_assert_eq!(LedgerEntry::decode(&bytes), Ok(entry));
        for (index, value) in flips {
            let i = index.index(bytes.len());
            bytes[i] = value;
        }
        if let Ok(decoded) = LedgerEntry::decode(&bytes) {
            prop_assert_eq!(decoded.encode(), bytes.clone());
        }
        let truncated = &bytes[..cut.index(bytes.len())];
        if let Ok(decoded) = LedgerEntry::decode(truncated) {
            prop_assert_eq!(decoded.encode(), truncated.to_vec());
        }
    }

    /// Proof verification on garbage must return false, not panic, and must
    /// never accept a proof for a different index.
    #[test]
    fn proof_verification_is_total(
        n in 1usize..64,
        index in any::<prop::sample::Index>(),
        claimed_index in 0u64..80,
        claimed_size in 0u64..80,
        junk in proptest::collection::vec(any::<[u8; 32]>(), 0..8),
    ) {
        let leaves: Vec<_> = (0..n as u32).map(|i| merkle::leaf_hash(&i.to_be_bytes())).collect();
        let root = merkle::root(&leaves);
        let i = index.index(n);
        let proof = merkle::inclusion_proof(&leaves, i).unwrap();
        // The size isn't checked on its own (sizes 33 and 34 give leaf 0 the
        // same path shape); a signed tree head binds size and root together.
        let ok = merkle::verify_inclusion(&leaves[i], claimed_index, n as u64, &proof, &root);
        prop_assert_eq!(ok, claimed_index == i as u64);
        let _ = merkle::verify_inclusion(&leaves[i], claimed_index, claimed_size, &junk, &root);
        let _ = merkle::verify_consistency(claimed_index, claimed_size, &root, &root, &junk);
    }
}
