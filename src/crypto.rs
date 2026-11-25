use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::sync::atomic::{Ordering, compiler_fence};
use subtle::ConstantTimeEq;

pub const PBKDF2_ITERATIONS: u32 = 600_000;
const MIN_PBKDF2_ITERATIONS: u32 = 10_000;
const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

pub fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf {
        // Volatile writes prevent dead-store elimination before drop.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub fn zeroize_string(s: &mut String) {
    // Zero bytes preserve UTF-8 invariants before clearing length.
    zeroize_bytes(unsafe { s.as_bytes_mut() });
    s.clear();
}

#[derive(Clone)]
pub struct PasswordVerifier {
    iterations: u32,
    salt: [u8; SALT_LEN],
    expected: [u8; KEY_LEN],
}

impl Drop for PasswordVerifier {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.salt);
        zeroize_bytes(&mut self.expected);
    }
}

impl std::fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordVerifier")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
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
        let mut salt_vec = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| "invalid base64url salt in owner_password_hash".to_owned())?;
        if salt_vec.len() != SALT_LEN {
            zeroize_bytes(&mut salt_vec);
            return Err("owner_password_hash salt must be 16 bytes".to_owned());
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);
        zeroize_bytes(&mut salt_vec);

        let mut hash_vec = URL_SAFE_NO_PAD.decode(parts[3]).map_err(|_| {
            zeroize_bytes(&mut salt);
            "invalid base64url digest in owner_password_hash".to_owned()
        })?;
        if hash_vec.len() != KEY_LEN {
            zeroize_bytes(&mut salt);
            zeroize_bytes(&mut hash_vec);
            return Err("owner_password_hash digest must be 32 bytes".to_owned());
        }
        let mut expected = [0u8; KEY_LEN];
        expected.copy_from_slice(&hash_vec);
        zeroize_bytes(&mut hash_vec);

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
        let matched = bool::from(derived.ct_eq(&self.expected));
        zeroize_bytes(&mut derived);
        matched
    }
}

pub fn random_token_b64(byte_len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; byte_len];
    if let Err(e) = getrandom::fill(&mut buf) {
        zeroize_bytes(&mut buf);
        return Err(format!("random source failed: {e}"));
    }
    let encoded = URL_SAFE_NO_PAD.encode(&buf);
    zeroize_bytes(&mut buf);
    Ok(encoded)
}

pub fn sha256_b64(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn sha256_bytes(input: &str) -> [u8; 32] {
    Sha256::digest(input.as_bytes()).into()
}

pub fn constant_time_sha256_eq(candidate: &str, expected_digest: &[u8; 32]) -> bool {
    let mut candidate_digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
    let matched = bool::from(candidate_digest.ct_eq(expected_digest));
    zeroize_bytes(&mut candidate_digest);
    matched
}

pub fn compute_auth_ref(resource_url: &str, grant_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(resource_url.as_bytes());
    hasher.update([0u8]);
    hasher.update(grant_id.as_bytes());
    format!("aref_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

const AEAD_VERSION: u8 = 1;
const AEAD_NONCE_LEN: usize = 16;
const AEAD_TAG_LEN: usize = 32;

pub struct Crypto {
    enc_key: [u8; KEY_LEN],
    mac_key: [u8; KEY_LEN],
}

impl Drop for Crypto {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.enc_key);
        zeroize_bytes(&mut self.mac_key);
    }
}

impl Crypto {
    pub fn new_random() -> Result<Self, String> {
        let mut master = [0u8; KEY_LEN];
        getrandom::fill(&mut master).map_err(|e| format!("random source failed: {e}"))?;
        let enc_key = hmac_sha256(&master, b"oauth2-mcp-gateway/aead/enc/v1");
        let mac_key = hmac_sha256(&master, b"oauth2-mcp-gateway/aead/mac/v1");
        zeroize_bytes(&mut master);
        Ok(Self { enc_key, mac_key })
    }

    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<String, String> {
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| format!("random source failed: {e}"))?;
        let mut ciphertext = plaintext.to_vec();
        self.apply_keystream(&nonce, &mut ciphertext);
        let tag = self.compute_tag(aad, &nonce, &ciphertext);

        let mut wire = Vec::with_capacity(1 + AEAD_NONCE_LEN + ciphertext.len() + AEAD_TAG_LEN);
        wire.push(AEAD_VERSION);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ciphertext);
        wire.extend_from_slice(&tag);
        Ok(URL_SAFE_NO_PAD.encode(&wire))
    }

    pub fn open(&self, aad: &[u8], token_b64: &str) -> Option<Vec<u8>> {
        let wire = URL_SAFE_NO_PAD.decode(token_b64).ok()?;
        if wire.len() < 1 + AEAD_NONCE_LEN + AEAD_TAG_LEN || wire[0] != AEAD_VERSION {
            return None;
        }
        let nonce = &wire[1..1 + AEAD_NONCE_LEN];
        let tag_offset = wire.len() - AEAD_TAG_LEN;
        let ciphertext = &wire[1 + AEAD_NONCE_LEN..tag_offset];
        let presented_tag = &wire[tag_offset..];

        let mut expected_tag = self.compute_tag(aad, nonce, ciphertext);
        let valid = bool::from(presented_tag.ct_eq(&expected_tag));
        zeroize_bytes(&mut expected_tag);
        if !valid {
            return None;
        }

        let mut plaintext = ciphertext.to_vec();
        self.apply_keystream(nonce, &mut plaintext);
        Some(plaintext)
    }

    fn apply_keystream(&self, nonce: &[u8], buf: &mut [u8]) {
        let prf = HmacPrecomputed::new(&self.enc_key);
        let mut block_input = [0u8; AEAD_NONCE_LEN + 8];
        block_input[..AEAD_NONCE_LEN].copy_from_slice(nonce);
        for (counter, chunk) in buf.chunks_mut(32).enumerate() {
            block_input[AEAD_NONCE_LEN..].copy_from_slice(&(counter as u64).to_be_bytes());
            let mut keystream = prf.mac(&block_input);
            for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
                *b ^= *k;
            }
            zeroize_bytes(&mut keystream);
        }
        zeroize_bytes(&mut block_input);
    }

    fn compute_tag(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> [u8; AEAD_TAG_LEN] {
        let mut msg = Vec::with_capacity(8 + aad.len() + nonce.len() + 8 + ciphertext.len());
        msg.extend_from_slice(&(aad.len() as u64).to_be_bytes());
        msg.extend_from_slice(aad);
        msg.extend_from_slice(nonce);
        msg.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
        msg.extend_from_slice(ciphertext);
        hmac_sha256(&self.mac_key, &msg)
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    HmacPrecomputed::new(key).mac(data)
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
            let mut hashed = Sha256::digest(key);
            key_block[..32].copy_from_slice(&hashed);
            zeroize_bytes(&mut hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }
        zeroize_bytes(&mut key_block);

        let mut inner_base = Sha256::new();
        inner_base.update(ipad);
        zeroize_bytes(&mut ipad);

        let mut outer_base = Sha256::new();
        outer_base.update(opad);
        zeroize_bytes(&mut opad);

        Self {
            inner_base,
            outer_base,
        }
    }

    fn mac(&self, data: &[u8]) -> [u8; 32] {
        let mut inner = self.inner_base.clone();
        inner.update(data);
        let mut inner_hash = inner.finalize();

        let mut outer = self.outer_base.clone();
        outer.update(inner_hash);
        zeroize_bytes(&mut inner_hash);
        outer.finalize().into()
    }
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8; 32]) {
    let prf = HmacPrecomputed::new(password);
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&1u32.to_be_bytes());

    let mut u = prf.mac(&salt_block);
    zeroize_bytes(&mut salt_block);
    let mut t = u;
    for _ in 1..iterations {
        u = prf.mac(&u);
        for i in 0..32 {
            t[i] ^= u[i];
        }
    }
    out.copy_from_slice(&t);
    zeroize_bytes(&mut u);
    zeroize_bytes(&mut t);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_and_hmac_match_rfc_vectors() {
        assert_eq!(PBKDF2_ITERATIONS, 600_000);
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

        let mac = hmac_sha256(&[0x0bu8; 20], b"Hi There");
        let mac_hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            mac_hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn password_verifier_roundtrips_and_zeroizes_buffers() {
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

        let mut s = String::from("temporary-secret");
        zeroize_string(&mut s);
        assert!(s.is_empty());
    }

    #[test]
    fn pkce_s256_matches_rfc_7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(is_valid_s256_challenge(challenge));
        assert!(verify_pkce_s256(verifier, challenge));
        assert!(!verify_pkce_s256("short", challenge));
    }

    #[test]
    fn crypto_aead_and_auth_ref_roundtrip_and_reject_tampering() {
        let crypto = Crypto::new_random().unwrap();
        let aad = b"https://mcp.example.com\0nonce-123";
        let plaintext = b"{\"client_id\":\"cli_1\",\"scopes\":[\"mcp\"]}";
        let sealed_a = crypto.seal(aad, plaintext).unwrap();
        let sealed_b = crypto.seal(aad, plaintext).unwrap();
        assert_ne!(sealed_a, sealed_b);
        assert_eq!(crypto.open(aad, &sealed_a).unwrap(), plaintext);
        assert!(
            crypto
                .open(b"https://mcp.example.com\0nonce-999", &sealed_a)
                .is_none()
        );

        let mut raw = URL_SAFE_NO_PAD.decode(&sealed_a).unwrap();
        let mid = 20;
        raw[mid] ^= 0x01;
        let tampered_ct = URL_SAFE_NO_PAD.encode(&raw);
        assert!(crypto.open(aad, &tampered_ct).is_none());

        let other_crypto = Crypto::new_random().unwrap();
        assert!(other_crypto.open(aad, &sealed_a).is_none());

        let aref = compute_auth_ref("https://mcp.example.com/mcp", "grt_abc");
        assert!(aref.starts_with("aref_"));
        assert_eq!(
            aref,
            format!(
                "aref_{}",
                sha256_b64("https://mcp.example.com/mcp\0grt_abc")
            )
        );

        let expected = sha256_bytes("0123456789abcdef_secret");
        assert!(constant_time_sha256_eq(
            "0123456789abcdef_secret",
            &expected
        ));
        assert!(!constant_time_sha256_eq("wrong", &expected));
    }
}
