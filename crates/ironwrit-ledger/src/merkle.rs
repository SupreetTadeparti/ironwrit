//! RFC 6962 / RFC 9162 Merkle tree hashing and proofs.
//!
//! Functions take the list of leaf hashes; the ledger keeps them in memory.

use sha2::{Digest, Sha256};

use crate::Hash;

/// `SHA-256(0x00 || data)`
pub fn leaf_hash(data: &[u8]) -> Hash {
    Sha256::new()
        .chain_update([0x00])
        .chain_update(data)
        .finalize()
        .into()
}

/// `SHA-256(0x01 || left || right)`
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new()
        .chain_update([0x01])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// Merkle tree hash of the leaves. The empty tree hashes to `SHA-256("")`.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path proving leaf `index` is in the tree of `leaves`
/// (RFC 6962 §2.1.1). `None` if `index` is out of range.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    path(index, leaves, &mut proof);
    Some(proof)
}

fn path(m: usize, leaves: &[Hash], proof: &mut Vec<Hash>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        path(m, &leaves[..k], proof);
        proof.push(root(&leaves[k..]));
    } else {
        path(m - k, &leaves[k..], proof);
        proof.push(root(&leaves[..k]));
    }
}

/// Proof that the tree of the first `old` leaves is a prefix of the tree of
/// all `leaves` (RFC 6962 §2.1.2). `None` unless `0 < old <= leaves.len()`.
pub fn consistency_proof(leaves: &[Hash], old: usize) -> Option<Vec<Hash>> {
    if old == 0 || old > leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    subproof(old, leaves, true, &mut proof);
    Some(proof)
}

fn subproof(m: usize, leaves: &[Hash], complete: bool, proof: &mut Vec<Hash>) {
    let n = leaves.len();
    if m == n {
        if !complete {
            proof.push(root(leaves));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &leaves[..k], complete, proof);
        proof.push(root(&leaves[k..]));
    } else {
        subproof(m - k, &leaves[k..], false, proof);
        proof.push(root(&leaves[..k]));
    }
}

/// Check an inclusion proof (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(leaf: &Hash, index: u64, size: u64, proof: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

/// Check a consistency proof between tree sizes `old` and `new`
/// (RFC 9162 §2.1.4.2).
pub fn verify_consistency(
    old: u64,
    new: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old == 0 || old > new {
        return false;
    }
    if old == new {
        return proof.is_empty() && old_root == new_root;
    }
    // A power-of-two old tree is a complete subtree; its root starts the path.
    let path: Vec<Hash> = if old.is_power_of_two() {
        std::iter::once(*old_root)
            .chain(proof.iter().copied())
            .collect()
    } else {
        proof.to_vec()
    };
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    let (mut f, mut s) = (old - 1, new - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (*first, *first);
    for c in rest {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    fr == *old_root && sr == *new_root && s == 0
}

/// Largest power of two strictly less than `n` (for `n > 1`).
fn split(n: usize) -> usize {
    1 << (usize::BITS - (n - 1).leading_zeros() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(hex: &str) -> Hash {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    /// Test vectors from the Certificate Transparency reference
    /// implementation (merkle_tree_test.cc).
    fn leaves() -> Vec<Hash> {
        [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|d| leaf_hash(&hex::decode(d).unwrap()))
        .collect()
    }

    const ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    #[test]
    fn empty_tree_root() {
        assert_eq!(
            root(&[]),
            h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn roots_match_reference_vectors() {
        let leaves = leaves();
        for (n, expected) in ROOTS.iter().enumerate() {
            assert_eq!(root(&leaves[..=n]), h(expected), "tree size {}", n + 1);
        }
    }

    #[test]
    fn inclusion_proofs_match_reference_vectors() {
        let leaves = leaves();
        let cases: &[(usize, usize, &[&str])] = &[
            (0, 1, &[]),
            (
                0,
                8,
                &[
                    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
                ],
            ),
            (
                5,
                8,
                &[
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
            (
                2,
                3,
                &["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
            ),
            (
                1,
                5,
                &[
                    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                ],
            ),
        ];
        for &(index, size, expected) in cases {
            let proof = inclusion_proof(&leaves[..size], index).unwrap();
            let expected: Vec<Hash> = expected.iter().map(|e| h(e)).collect();
            assert_eq!(proof, expected, "leaf {index} in tree {size}");
            assert!(verify_inclusion(
                &leaves[index],
                index as u64,
                size as u64,
                &proof,
                &h(ROOTS[size - 1])
            ));
        }
    }

    #[test]
    fn consistency_proofs_match_reference_vectors() {
        let leaves = leaves();
        let cases: &[(usize, usize, &[&str])] = &[
            (1, 1, &[]),
            (
                1,
                8,
                &[
                    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
                ],
            ),
            (
                6,
                8,
                &[
                    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
            (
                2,
                5,
                &[
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                ],
            ),
        ];
        for &(old, new, expected) in cases {
            let proof = consistency_proof(&leaves[..new], old).unwrap();
            let expected: Vec<Hash> = expected.iter().map(|e| h(e)).collect();
            assert_eq!(proof, expected, "{old} -> {new}");
            assert!(verify_consistency(
                old as u64,
                new as u64,
                &h(ROOTS[old - 1]),
                &h(ROOTS[new - 1]),
                &proof
            ));
        }
    }

    #[test]
    fn every_proof_verifies_and_tampering_fails() {
        let leaves: Vec<Hash> = (0u32..40).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        for n in 1..=leaves.len() {
            let tree = &leaves[..n];
            let r = root(tree);
            for i in 0..n {
                let proof = inclusion_proof(tree, i).unwrap();
                assert!(verify_inclusion(&tree[i], i as u64, n as u64, &proof, &r));
                assert!(!verify_inclusion(&[0; 32], i as u64, n as u64, &proof, &r));
                if n > 1 {
                    let other = (i + 1) % n;
                    assert!(!verify_inclusion(
                        &tree[i],
                        other as u64,
                        n as u64,
                        &proof,
                        &r
                    ));
                }
            }
            for m in 1..=n {
                let proof = consistency_proof(tree, m).unwrap();
                let old = root(&tree[..m]);
                assert!(verify_consistency(m as u64, n as u64, &old, &r, &proof));
                if m < n {
                    assert!(!verify_consistency(m as u64, n as u64, &r, &r, &proof));
                    let mut bad = proof.clone();
                    bad[0][0] ^= 1;
                    assert!(!verify_consistency(m as u64, n as u64, &old, &r, &bad));
                }
            }
        }
    }

    #[test]
    fn out_of_range_requests_are_refused() {
        let leaves = leaves();
        assert!(inclusion_proof(&leaves, 8).is_none());
        assert!(consistency_proof(&leaves, 0).is_none());
        assert!(consistency_proof(&leaves, 9).is_none());
        assert!(!verify_inclusion(&leaves[0], 1, 1, &[], &leaves[0]));
        assert!(!verify_consistency(0, 1, &leaves[0], &leaves[0], &[]));
    }
}
