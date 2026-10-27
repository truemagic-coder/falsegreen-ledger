//! Integrity anchors: the Merkle root of a shard's record hashes and the
//! Ed25519 seal that signs it. The seal is the external trust anchor — a
//! verifier who holds the public key can confirm the shard without the
//! signer.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::chain::is_valid_hash;
use crate::store::{seal_signing_message, Seal};

/// Merkle root over a shard's record hashes: pairwise SHA-256 over the
/// concatenated pair (hex-decoded), an odd leaf pairs with itself. The
/// input order is the shard's record order.
pub fn merkle_root(record_hashes: &[String]) -> Result<String, String> {
    let mut level: Vec<Vec<u8>> = record_hashes
        .iter()
        .map(|h| hex::decode(h).map_err(|e| format!("record hash is not hex: {e}")))
        .collect::<Result<_, _>>()?;
    if level.is_empty() {
        return Err("merkle root of an empty shard is undefined".to_string());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() == 2 {
                &chunk[1]
            } else {
                &chunk[0]
            };
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().to_vec());
        }
        level = next;
    }
    Ok(hex::encode(
        level.pop().expect("the loop stops at one node"),
    ))
}

/// Sign a seal: compute the Ed25519 signature over [`seal_signing_message`]
/// and fill in the seal's `signature` + `public_key` fields.
pub fn sign_seal(mut seal: Seal, private_key_hex: &str) -> Result<Seal, String> {
    let key = SigningKey::from_bytes(
        &hex::decode(private_key_hex)
            .map_err(|_| "private key is not hex".to_string())?
            .as_slice()
            .try_into()
            .map_err(|_| "private key is not 32 bytes".to_string())?,
    );
    let message = seal_signing_message(&seal);
    let sig = key.sign(&message);
    seal.signature = hex::encode(sig.to_bytes());
    seal.public_key = hex::encode(key.verifying_key().to_bytes());
    Ok(seal)
}

/// Verify a seal's signature against its embedded public key.
pub fn verify_seal(seal: &Seal) -> Result<(), String> {
    verify_seal_with(seal, &seal.public_key)
}

/// Verify a seal's signature against a specific trusted public key (the
/// embedded key must equal it — a swapped key is a failure, not a pass).
pub fn verify_seal_with(seal: &Seal, trusted_public_key_hex: &str) -> Result<(), String> {
    if !is_valid_hash(&seal.public_key) {
        return Err("seal public_key is not a 32-byte hex key".to_string());
    }
    if seal.public_key != trusted_public_key_hex {
        return Err("seal public_key is not the trusted key".to_string());
    }
    check_signature(seal)
}

fn check_signature(seal: &Seal) -> Result<(), String> {
    let sig_bytes =
        hex::decode(&seal.signature).map_err(|_| "seal signature is not hex".to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("invalid signature: {e}"))?;
    let key_bytes =
        hex::decode(&seal.public_key).map_err(|_| "seal public_key is not hex".to_string())?;
    let key = VerifyingKey::from_bytes(
        &key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "seal public_key is not 32 bytes".to_string())?,
    )
    .map_err(|e| format!("invalid public key: {e}"))?;
    key.verify(&seal_signing_message(seal), &sig)
        .map_err(|e| format!("seal signature does not verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn sample_hashes(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let mut h = Sha256::new();
                h.update(i.to_le_bytes());
                hex::encode(h.finalize())
            })
            .collect()
    }

    fn unsigned_seal(root: String, count: u64) -> Seal {
        Seal {
            merkle_root: root,
            count,
            prev_shard_root: None,
            signature: String::new(),
            public_key: String::new(),
            sealed_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn merkle_root_is_deterministic_and_order_sensitive() {
        let h = sample_hashes(7);
        let a = merkle_root(&h).unwrap();
        let b = merkle_root(&h).unwrap();
        assert_eq!(a, b);
        assert!(is_valid_hash(&a));
        let mut h2 = h.clone();
        h2.push(h2[0].clone());
        let c = merkle_root(&h2).unwrap();
        assert_ne!(a, c, "a different shard must give a different root");
        let mut h3 = h.clone();
        h3.swap(0, 2);
        assert_ne!(a, merkle_root(&h3).unwrap(), "reordering changes the root");
    }

    #[test]
    fn merkle_root_rejects_empty_and_non_hex() {
        assert!(merkle_root(&[]).is_err());
        assert!(merkle_root(&["zz".into()]).is_err());
    }

    #[test]
    fn a_lone_leaf_is_its_own_root_and_odd_leaves_pair_with_themselves() {
        let h = sample_hashes(3);
        let root = merkle_root(&h).unwrap();
        let dec: Vec<Vec<u8>> = h.iter().map(|x| hex::decode(x).unwrap()).collect();
        let mut m12 = Sha256::new();
        m12.update(&dec[0]);
        m12.update(&dec[1]);
        let m12 = m12.finalize();
        let mut m33 = Sha256::new();
        m33.update(&dec[2]);
        m33.update(&dec[2]);
        let m33 = m33.finalize();
        let mut root_h = Sha256::new();
        root_h.update(m12);
        root_h.update(m33);
        assert_eq!(
            root,
            hex::encode(root_h.finalize()),
            "odd leaf pairs with itself"
        );
        assert_eq!(
            merkle_root(&h[0..1]).unwrap(),
            h[0],
            "a lone leaf is its own root"
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let priv_hex = hex::encode(key.to_bytes());
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        let root = merkle_root(&sample_hashes(3)).unwrap();
        let seal = sign_seal(unsigned_seal(root, 3), &priv_hex).unwrap();
        assert_eq!(seal.public_key, pub_hex);
        assert!(verify_seal(&seal).is_ok());
        assert!(verify_seal_with(&seal, &pub_hex).is_ok());
    }

    #[test]
    fn a_tampered_seal_field_fails_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let priv_hex = hex::encode(key.to_bytes());
        let root = merkle_root(&sample_hashes(3)).unwrap();
        let mut seal = sign_seal(unsigned_seal(root.clone(), 3), &priv_hex).unwrap();
        seal.count = 4;
        assert!(verify_seal(&seal).is_err(), "a flipped count must fail");
        let mut seal = sign_seal(unsigned_seal(root.clone(), 3), &priv_hex).unwrap();
        let mut sig = hex::decode(&seal.signature).unwrap();
        sig[0] ^= 0x01;
        seal.signature = hex::encode(sig);
        assert!(verify_seal(&seal).is_err(), "a flipped signature must fail");
        let mut seal = sign_seal(unsigned_seal(root.clone(), 3), &priv_hex).unwrap();
        seal.sealed_at_ms -= 1;
        assert!(verify_seal(&seal).is_err(), "a flipped timestamp must fail");
    }

    #[test]
    fn the_trusted_key_must_match_the_embedded_key() {
        let key = SigningKey::generate(&mut OsRng);
        let root = merkle_root(&sample_hashes(1)).unwrap();
        let seal = sign_seal(unsigned_seal(root, 1), &hex::encode(key.to_bytes())).unwrap();
        let other = SigningKey::generate(&mut OsRng);
        let other_pub = hex::encode(other.verifying_key().to_bytes());
        assert_ne!(seal.public_key, other_pub);
        assert!(
            verify_seal_with(&seal, &other_pub).is_err(),
            "a seal from a different signer must not verify under the trusted key"
        );
    }

    #[test]
    fn malformed_keys_and_signatures_are_rejected() {
        let mut seal = unsigned_seal(merkle_root(&sample_hashes(1)).unwrap(), 1);
        seal.public_key = "not-hex".into();
        assert!(verify_seal(&seal).is_err());
        let key = SigningKey::generate(&mut OsRng);
        seal.public_key = hex::encode(key.verifying_key().to_bytes());
        seal.signature = "ab".into();
        assert!(verify_seal(&seal).is_err());
    }
}
