//! Signed releases. A release is trusted only if its signature verifies with one of the public keys built into the
//! agent: the main key (kept only on the maintainer's laptop) or the backup key (kept separately). The control centre
//! only distributes releases and cannot sign them.
//!
//! The test key exists only in a development build (`--features dev`); a release build never accepts it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub const PREFIX: &str = "cybercop-agent-release-v1";

/// Production public keys (base64, Ed25519). Filled in before the first build for clients; until then a release build
/// trusts no key and refuses every update.
pub const PRODUCTION_KEYS: &[(&str, &str)] = &[];

/// Test key for development and automated tests. Its secret half is in the test code and is public on purpose.
pub const TEST_KEY: (&str, &str) = ("test", "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=");

pub fn trusted_keys() -> Vec<(&'static str, &'static str)> {
    let mut keys: Vec<(&str, &str)> = PRODUCTION_KEYS.to_vec();
    if cfg!(feature = "dev") {
        keys.push(TEST_KEY);
    }
    keys
}

pub fn message(version: &str, arch: &str, sha256: &str) -> Vec<u8> {
    format!("{PREFIX}\n{version}\n{arch}\n{sha256}").into_bytes()
}

/// → the name of the key that signed the release, or an error.
pub fn verify(version: &str, arch: &str, sha256: &str, signature_b64: &str) -> Result<&'static str, String> {
    verify_with(&trusted_keys(), version, arch, sha256, signature_b64)
}

pub fn verify_with(keys: &[(&'static str, &'static str)], version: &str, arch: &str, sha256: &str, signature_b64: &str) -> Result<&'static str, String> {
    if keys.is_empty() {
        return Err("no trusted signing keys in this build".into());
    }
    let sig_bytes = B64.decode(signature_b64).map_err(|_| "bad signature encoding".to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "bad signature".to_string())?;
    let msg = message(version, arch, sha256);
    for (name, key) in keys {
        let Ok(raw) = B64.decode(key) else { continue };
        let Ok(raw) = <[u8; 32]>::try_from(raw.as_slice()) else { continue };
        let Ok(vk) = VerifyingKey::from_bytes(&raw) else { continue };
        if vk.verify(&msg, &sig).is_ok() {
            return Ok(name);
        }
    }
    Err("the signature does not match any trusted key".into())
}

/// a.b.c strictly newer than the running version (no downgrades).
pub fn newer(candidate: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<(u64, u64, u64)> {
        let mut it = v.split('.').map(|x| x.parse::<u64>().ok());
        Some((it.next()??, it.next()??, it.next()??))
    }
    matches!((parse(candidate), parse(current)), (Some(a), Some(b)) if a > b)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Secret half of TEST_KEY (public on purpose: it is only for development builds and tests).
    pub const TEST_SECRET: [u8; 32] = [7u8; 32];

    fn sign(key: &SigningKey, v: &str, a: &str, s: &str) -> String {
        B64.encode(key.sign(&message(v, a, s)).to_bytes())
    }

    #[test]
    fn test_key_matches_its_secret() {
        let k = SigningKey::from_bytes(&TEST_SECRET);
        assert_eq!(B64.encode(k.verifying_key().to_bytes()), TEST_KEY.1);
    }

    #[test]
    fn release_build_never_trusts_the_test_key() {
        if !cfg!(feature = "dev") {
            assert!(!trusted_keys().contains(&TEST_KEY));
            let k = SigningKey::from_bytes(&TEST_SECRET);
            assert!(verify("9.9.9", "x86_64", "ab", &sign(&k, "9.9.9", "x86_64", "ab")).is_err());
        }
        assert!(!PRODUCTION_KEYS.iter().any(|(_, k)| *k == TEST_KEY.1));
    }

    #[test]
    fn refuses_foreign_signature_and_tampering() {
        let main = SigningKey::from_bytes(&[1u8; 32]);
        let backup = SigningKey::from_bytes(&[2u8; 32]);
        let stranger = SigningKey::from_bytes(&[3u8; 32]);
        let pk = |k: &SigningKey| -> &'static str { Box::leak(B64.encode(k.verifying_key().to_bytes()).into_boxed_str()) };
        let keys = [("main", pk(&main)), ("backup", pk(&backup))];
        let good = sign(&main, "0.2.0", "x86_64", "aa");
        assert_eq!(verify_with(&keys, "0.2.0", "x86_64", "aa", &good), Ok("main"));
        assert_eq!(verify_with(&keys, "0.2.0", "x86_64", "aa", &sign(&backup, "0.2.0", "x86_64", "aa")), Ok("backup"));
        assert!(verify_with(&keys, "0.2.0", "x86_64", "aa", &sign(&stranger, "0.2.0", "x86_64", "aa")).is_err());
        assert!(verify_with(&keys, "0.2.0", "x86_64", "bb", &good).is_err()); // another file
        assert!(verify_with(&keys, "0.3.0", "x86_64", "aa", &good).is_err()); // another version
        assert!(verify_with(&[], "0.2.0", "x86_64", "aa", &good).is_err());
    }

    #[test]
    fn versions() {
        assert!(newer("0.2.0", "0.1.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.0.9", "0.1.0"));
        assert!(!newer("x", "0.1.0"));
    }
}
