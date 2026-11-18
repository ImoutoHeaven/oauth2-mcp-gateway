use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const PBKDF2_ITERATIONS: u32 = 210_000;
const MIN_PBKDF2_ITERATIONS: u32 = 10_000;
const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct PasswordVerifier {
    iterations: u32,
    salt: [u8; SALT_LEN],
    expected: [u8; KEY_LEN],
}

impl PasswordVerifier {
    pub fn from_plaintext(password: &str) -> Result<Self, String> {
        Self::from_plaintext_with_iterations(password, PBKDF2_ITERATIONS)
    }

    pub fn from_plaintext_with_iterations(password: &str, iterations: u32) -> Result<Self, String> {
        if password.is_empty() {
            return Err("owner password must not be empty".to_owned());
        }
        if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
            return Err(format!(
                "PBKDF2 iterations must be between {MIN_PBKDF2_ITERATIONS} and {MAX_PBKDF2_ITERATIONS}"
            ));
        }
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|e| format!("random source failed: {e}"))?;
        let mut expected = [0u8; KEY_LEN];
        pbkdf2_hmac_sha256(password.as_bytes(), &salt, iterations, &mut expected);
        Ok(Self {
            iterations,
            salt,
            expected,
        })
    }

    pub fn parse_encoded(encoded: &str) -> Result<Self, String> {
        let parts: Vec<&str> = encoded.split('$').collect();
        if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
            return Err(
                "owner_password_hash must have format pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>"
                    .to_owned(),
            );
        }
        let iterations: u32 = parts[1]
            .parse()
            .map_err(|_| "invalid PBKDF2 iteration count".to_owned())?;
        if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
            return Err(format!(
                "PBKDF2 iterations must be between {MIN_PBKDF2_ITERATIONS} and {MAX_PBKDF2_ITERATIONS}"
            ));
        }
        let salt_vec = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| "invalid base64url salt in owner_password_hash".to_owned())?;
        let salt: [u8; SALT_LEN] = salt_vec
            .try_into()
            .map_err(|_| "owner_password_hash salt must be 16 bytes".to_owned())?;
        let hash_vec = URL_SAFE_NO_PAD
            .decode(parts[3])
            .map_err(|_| "invalid base64url digest in owner_password_hash".to_owned())?;
        let expected: [u8; KEY_LEN] = hash_vec
            .try_into()
            .map_err(|_| "owner_password_hash digest must be 32 bytes".to_owned())?;
        Ok(Self {
            iterations,
            salt,
            expected,
        })
    }

    pub fn encode(&self) -> String {
        format!(
            "pbkdf2-sha256${}${}${}",
            self.iterations,
            URL_SAFE_NO_PAD.encode(self.salt),
            URL_SAFE_NO_PAD.encode(self.expected)
        )
    }

    pub fn verify(&self, candidate: &str) -> bool {
        if candidate.is_empty() {
            return false;
        }
        let mut derived = [0u8; KEY_LEN];
        pbkdf2_hmac_sha256(
            candidate.as_bytes(),
            &self.salt,
            self.iterations,
            &mut derived,
        );
        bool::from(derived.ct_eq(&self.expected))
    }
}

pub fn random_token_b64(byte_len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; byte_len];
    getrandom::fill(&mut buf).map_err(|e| format!("random source failed: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

pub fn sha256_b64(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn constant_time_eq_str(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    if !(43..=128).contains(&code_verifier.len()) || !is_pkce_unreserved(code_verifier) {
        return false;
    }
    if !(43..=128).contains(&code_challenge.len()) {
        return false;
    }
    let computed = sha256_b64(code_verifier);
    constant_time_eq_str(&computed, code_challenge)
}

pub fn is_valid_s256_challenge(code_challenge: &str) -> bool {
    if !(43..=128).contains(&code_challenge.len()) {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(code_challenge)
        .is_ok_and(|decoded| decoded.len() == 32)
}

fn is_pkce_unreserved(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

struct HmacPrecomputed {
    inner_base: Sha256,
    outer_base: Sha256,
}

impl HmacPrecomputed {
    fn new(key: &[u8]) -> Self {
        const BLOCK_LEN: usize = 64;
        let mut key_block = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            let hashed = Sha256::digest(key);
            key_block[..32].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }

        let mut inner_base = Sha256::new();
        inner_base.update(ipad);
        let mut outer_base = Sha256::new();
        outer_base.update(opad);
        Self {
            inner_base,
            outer_base,
        }
    }

    fn mac(&self, data: &[u8]) -> [u8; 32] {
        let mut inner = self.inner_base.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = self.outer_base.clone();
        outer.update(inner_hash);
        outer.finalize().into()
    }
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8; 32]) {
    let prf = HmacPrecomputed::new(password);
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&1u32.to_be_bytes());

    let mut u = prf.mac(&salt_block);
    let mut t = u;
    for _ in 1..iterations {
        u = prf.mac(&u);
        for i in 0..32 {
            t[i] ^= u[i];
        }
    }
    out.copy_from_slice(&t);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_rfc_7914_test_vector() {
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut out);
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        let mut out4096 = [0u8; 32];
        pbkdf2_hmac_sha256(b"password", b"salt", 4096, &mut out4096);
        let hex4096: String = out4096.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex4096,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn password_verifier_roundtrips_and_rejects_wrong_secret() {
        let v = PasswordVerifier::from_plaintext_with_iterations(
            "correct-horse-battery-staple",
            10_000,
        )
        .unwrap();
        let encoded = v.encode();
        let parsed = PasswordVerifier::parse_encoded(&encoded).unwrap();
        assert!(parsed.verify("correct-horse-battery-staple"));
        assert!(!parsed.verify("wrong-secret"));
        assert!(!parsed.verify(""));
    }

    #[test]
    fn pkce_s256_matches_rfc_7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(is_valid_s256_challenge(challenge));
        assert!(verify_pkce_s256(verifier, challenge));
        assert!(!verify_pkce_s256("short", challenge));
    }
}
