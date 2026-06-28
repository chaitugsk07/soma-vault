//! Envelope encryption for soma-vault: per-version DEK, AES-256-GCM, AES-KW key wrap.
//!
//! # Design
//!
//! Each secret version gets a fresh 256-bit data-encryption-key (DEK).
//! The DEK is wrapped under a **per-tenant KEK** (AES-KW / RFC 3394) derived from
//! the master KEK via HKDF-SHA256.  Plaintext DEKs exist in pod memory only for the
//! duration of an operation, then are zeroized.
//!
//! # Key hierarchy
//!
//! ```text
//! MasterKek  ──HKDF──▶  TenantKek(tenant_id)  ──AES-KW──▶  DEK  ──AES-GCM──▶  ciphertext
//! ```
//!
//! # Ponytail ceiling
//!
//! Software-KEK is the lean-MVP fallback — a Postgres dump PLUS the
//! `SOMA_MASTER_KEK_HEX` env var = plaintext; this is NOT the production
//! auto-unseal posture (KMS-by-workload-identity is the Phase-2 upgrade;
//! `seal_provider`/`seal_key_id` + `rewrap_dek` make that a non-breaking
//! re-wrap, not a data migration).
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use aes_gcm::{
    aead::{Aead, AeadCore, OsRng},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

// ── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the `soma-crypto` crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The hex string supplied for the KEK was invalid (wrong length or non-hex chars).
    #[error("invalid key format: {0}")]
    KeyFormat(String),

    /// AES-KW unwrap failed (wrong KEK or corrupted wrapped DEK).
    #[error("key unwrap failed")]
    Unwrap,

    /// AES-256-GCM decryption failed (wrong key, tampered ciphertext, or wrong AAD).
    #[error("decryption failed")]
    Decrypt,

    /// AAD mismatch detected by `decrypt_checked` (wrong `secret_id` or version).
    #[error("AAD mismatch: expected secret_id/version do not match sealed envelope")]
    AadMismatch,

    /// Failed to produce random bytes from the OS RNG.
    #[error("RNG error")]
    Rng,

    /// AES-KW wrap failed (should not occur with a valid 32-byte DEK).
    #[error("key wrap failed")]
    Wrap,
}

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// ── SealProvider ─────────────────────────────────────────────────────────────

/// Which key-management backend wrapped the DEK.
///
/// The DB column stores the [`as_str`][SealProvider::as_str] representation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealProvider {
    /// Software AES-KW, KEK from env var. Lean-MVP fallback.
    Software,
    /// AWS KMS (Phase 2).
    AwsKms,
    /// GCP Cloud KMS (Phase 2).
    GcpKms,
    /// Azure Key Vault (Phase 2).
    AzureKms,
}

impl SealProvider {
    /// Returns the DB-safe lowercase string for this provider.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::AwsKms => "aws_kms",
            Self::GcpKms => "gcp_kms",
            Self::AzureKms => "azure_kms",
        }
    }
}

impl std::fmt::Display for SealProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SealProvider {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "software" => Ok(Self::Software),
            "aws_kms" => Ok(Self::AwsKms),
            "gcp_kms" => Ok(Self::GcpKms),
            "azure_kms" => Ok(Self::AzureKms),
            other => Err(Error::KeyFormat(format!("unknown seal_provider: {other}"))),
        }
    }
}

// ── MasterKek ────────────────────────────────────────────────────────────────

// ponytail: software-KEK is the lean-MVP fallback — a Postgres dump PLUS the
// `SOMA_MASTER_KEK_HEX` env var = plaintext; this is NOT the production
// auto-unseal posture (KMS-by-workload-identity is the Phase-2 upgrade;
// `seal_provider`/`seal_key_id` + `rewrap_dek` make that a non-breaking
// re-wrap, not a data migration).

/// A 32-byte master key-encryption-key (KEK).
///
/// The master KEK's only job is to derive per-tenant [`TenantKek`]s via HKDF.
/// DEKs are wrapped under `TenantKek`, never directly under `MasterKek`.
/// The bytes are zeroized on drop. Never log, serialize, or transmit this value.
pub struct MasterKek(Zeroizing<[u8; 32]>);

impl MasterKek {
    /// Load the KEK from the `SOMA_MASTER_KEK_HEX` environment variable.
    ///
    /// The raw hex string is held in a [`Zeroizing`] buffer and cleared from
    /// memory immediately after decoding.  Callers should also call
    /// `std::env::remove_var("SOMA_MASTER_KEK_HEX")` after this returns so the
    /// hex value is not readable via `/proc/self/environ`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyFormat`] if the env var is absent, not exactly 64 hex
    /// characters, or contains non-hex characters.
    pub fn from_hex_env() -> Result<Self> {
        // QW-2: wrap the raw hex in Zeroizing so the heap buffer is zeroed when
        // this function returns, whether via Ok or Err.
        let hex_str: Zeroizing<String> = std::env::var("SOMA_MASTER_KEK_HEX")
            .map(Zeroizing::new)
            .map_err(|_| Error::KeyFormat("SOMA_MASTER_KEK_HEX not set".into()))?;
        Self::from_hex(&hex_str)
    }

    /// Parse a KEK from a 64-character hex string (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyFormat`] if the string is not exactly 64 hex characters.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        if hex_str.len() != 64 {
            return Err(Error::KeyFormat(format!(
                "expected 64 hex chars, got {}",
                hex_str.len()
            )));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(hex_str, bytes.as_mut())
            .map_err(|e| Error::KeyFormat(format!("hex decode error: {e}")))?;
        Ok(Self(bytes))
    }

    /// Generate a fresh random KEK and return it as a 64-character lowercase hex string.
    ///
    /// Use for `soma keygen` — print the result and store it in a secrets manager.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the OS RNG fails (should not occur in practice).
    pub fn generate() -> Result<String> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| Error::Rng)?;
        Ok(hex::encode(bytes.as_ref()))
    }

    /// Compute a stable fingerprint of this KEK used as `seal_key_id`.
    ///
    /// Format: `"sw:" + hex(sha256(kek)[..8])` — identifies the KEK without
    /// exposing it. Enables future re-key detection.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0.as_ref());
        format!("sw:{}", hex::encode(&digest[..8]))
    }

    /// Derive a per-tenant KEK from this master KEK using HKDF-SHA256.
    ///
    /// The derivation is deterministic: the same master KEK + tenant UUID always
    /// yields the same `TenantKek`, so it can be re-derived at each request
    /// without storage.
    ///
    /// - IKM  = master KEK bytes
    /// - salt = `b"soma-vault-tenant-kek-v1"` (fixed app-specific constant)
    /// - info = `tenant_id.as_bytes()` (16-byte UUID)
    ///
    /// # Panics
    ///
    /// Never panics in practice: HKDF-SHA256 expansion is infallible for output
    /// lengths ≤ 255 × 32 = 8 160 bytes; 32 bytes is well within that limit.
    #[must_use]
    pub fn derive_tenant_kek(&self, tenant_id: Uuid) -> TenantKek {
        // ponytail: HKDF expand is infallible for output lengths ≤ 255 * hash_len.
        // 32 bytes << 255 * 32, so the unwrap is safe.
        const SALT: &[u8] = b"soma-vault-tenant-kek-v1";
        let derived = soma_infra::crypto::hkdf_sha256(
            self.0.as_ref(),
            Some(SALT),
            tenant_id.as_bytes(),
            32,
        )
        .expect("32 bytes is a valid HKDF output length");
        let mut okm = Zeroizing::new([0u8; 32]);
        okm.copy_from_slice(&derived);
        TenantKek(okm)
    }

    /// Derive a 32-byte HMAC key for audit log `entry_hash` computation.
    ///
    /// - IKM  = master KEK bytes
    /// - salt = `b"soma-vault-audit-hmac-v1"` (fixed constant)
    /// - info = `b"audit"` (distinguisher)
    ///
    /// The same master KEK always yields the same audit key. This key is
    /// used to HMAC-SHA256 each audit entry for tamper detection.
    ///
    /// # Panics
    ///
    /// Never panics in practice: HKDF-SHA256 expansion is infallible for output
    /// lengths ≤ 255 × 32 = 8 160 bytes; 32 bytes is well within that limit.
    #[must_use]
    pub fn derive_audit_hmac_key(&self) -> [u8; 32] {
        const SALT: &[u8] = b"soma-vault-audit-hmac-v1";
        let derived = soma_infra::crypto::hkdf_sha256(
            self.0.as_ref(),
            Some(SALT),
            b"audit",
            32,
        )
        .expect("32 bytes is a valid HKDF output length");
        let mut okm = [0u8; 32];
        okm.copy_from_slice(&derived);
        okm
    }
}

// ── TenantKek ─────────────────────────────────────────────────────────────────

/// A 32-byte per-tenant key-encryption-key derived from a [`MasterKek`].
///
/// DEKs are wrapped under this key (AES-KW / RFC 3394), never under the master
/// KEK directly.  Bytes are zeroized on drop.
pub struct TenantKek(Zeroizing<[u8; 32]>);

impl TenantKek {
    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ── Sealed ───────────────────────────────────────────────────────────────────

/// An encrypted secret version — all fields needed to persist to `fct_secret_versions`.
#[derive(Clone)]
pub struct Sealed {
    /// AES-256-GCM ciphertext (includes the 16-byte GCM authentication tag).
    pub ciphertext: Vec<u8>,
    /// 12-byte (96-bit) random GCM nonce.
    pub nonce: Vec<u8>,
    /// AES-KW wrapped DEK (40 bytes for a 32-byte key per RFC 3394).
    pub wrapped_dek: Vec<u8>,
    /// 24-byte AAD: `secret_id.as_bytes() (16) ‖ version.to_be_bytes() (8)`.
    pub aad: Vec<u8>,
    /// Which KMS backend wrapped the DEK.
    pub seal_provider: SealProvider,
    /// Fingerprint identifying which KEK wrapped the DEK (e.g. `"sw:aabbccdd11223344"`).
    pub seal_key_id: String,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce_len", &self.nonce.len())
            .field("wrapped_dek", &"[redacted]")
            .field("aad_len", &self.aad.len())
            .field("seal_provider", &self.seal_provider)
            .field("seal_key_id", &self.seal_key_id)
            .finish()
    }
}

// ── Core functions ────────────────────────────────────────────────────────────

/// Encrypt `plaintext` under a fresh DEK, then wrap the DEK under the tenant KEK.
///
/// `secret_id` and `version` are bound into the GCM AAD so this ciphertext
/// cannot be replayed into a different row without detection.
///
/// # Errors
///
/// - [`Error::Rng`] — OS RNG failed to produce random bytes
/// - [`Error::Wrap`] — AES-KW wrap failed (should not occur with a valid 32-byte key)
pub fn encrypt(
    kek: &TenantKek,
    secret_id: Uuid,
    version: i64,
    plaintext: &[u8],
) -> Result<Sealed> {
    // 1. Fresh 32-byte DEK from OS RNG
    let mut dek = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(dek.as_mut())
        .map_err(|_| Error::Rng)?;

    // 2. Build AAD = secret_id bytes (16) ‖ version big-endian (8) = 24 bytes
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(secret_id.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());

    // 3. AES-256-GCM encrypt with a fresh 12-byte nonce
    let cipher = Aes256Gcm::new(dek.as_ref().into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Rng)?;

    // 4. Wrap DEK under tenant KEK (AES-KW / RFC 3394) → 40 bytes
    let kek_obj: aes_kw::KekAes256 = (*kek.bytes()).into();
    let wrapped_dek = kek_obj.wrap_vec(dek.as_ref()).map_err(|_| Error::Wrap)?;

    // DEK is dropped and zeroized here by Zeroizing<>

    // seal_key_id is derived from the master KEK fingerprint at the call site;
    // here we produce a placeholder that the storage layer overwrites if needed.
    // ponytail: TenantKek has no fingerprint method — callers pass the master fingerprint.
    Ok(Sealed {
        ciphertext,
        nonce: nonce.to_vec(),
        wrapped_dek,
        aad,
        seal_provider: SealProvider::Software,
        seal_key_id: String::new(), // filled in by caller
    })
}

/// Decrypt a [`Sealed`] envelope, returning plaintext in a zeroizing buffer.
///
/// The GCM authentication tag covers both ciphertext and `sealed.aad`, so any
/// tamper or AAD mismatch produces [`Error::Decrypt`].
///
/// # Errors
///
/// - [`Error::Unwrap`] — wrong KEK or corrupted `wrapped_dek`
/// - [`Error::Decrypt`] — GCM auth failure (tampered bytes, wrong AAD, or wrong key after unwrap)
pub fn decrypt(kek: &TenantKek, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    // 1. Unwrap DEK under tenant KEK
    let kek_obj: aes_kw::KekAes256 = (*kek.bytes()).into();
    let mut dek_vec = kek_obj
        .unwrap_vec(&sealed.wrapped_dek)
        .map_err(|_| Error::Unwrap)?;

    if dek_vec.len() != 32 {
        dek_vec.zeroize();
        return Err(Error::Unwrap);
    }

    // 2. AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&dek_vec).map_err(|_| {
        dek_vec.zeroize();
        Error::Unwrap
    })?;
    let nonce = Nonce::<aes_gcm::aead::generic_array::typenum::U12>::from_slice(&sealed.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &sealed.ciphertext,
                aad: &sealed.aad,
            },
        )
        .map_err(|_| {
            dek_vec.zeroize();
            Error::Decrypt
        })?;

    // 3. Zeroize DEK
    dek_vec.zeroize();

    Ok(Zeroizing::new(plaintext))
}

/// Like [`decrypt`], but first verifies `sealed.aad` matches the expected values.
///
/// Rebuilds the expected 24-byte AAD from `expected_secret_id` and
/// `expected_version` and compares in constant time before decrypting.
/// This is defense in depth — GCM already covers AAD, but this check catches
/// accidental row mismatches before touching crypto.
///
/// # Errors
///
/// - [`Error::AadMismatch`] — the provided values don't match the envelope AAD
/// - [`Error::Unwrap`] / [`Error::Decrypt`] — propagated from [`decrypt`]
pub fn decrypt_checked(
    kek: &TenantKek,
    sealed: &Sealed,
    expected_secret_id: Uuid,
    expected_version: i64,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut expected_aad = Vec::with_capacity(24);
    expected_aad.extend_from_slice(expected_secret_id.as_bytes());
    expected_aad.extend_from_slice(&expected_version.to_be_bytes());

    let aad_ok: bool = expected_aad.ct_eq(&sealed.aad).into();
    if !aad_ok {
        return Err(Error::AadMismatch);
    }

    decrypt(kek, sealed)
}

/// Compute HMAC-SHA256 over `msg` using `key`, returning hex-encoded output.
///
/// Used by the audit log to produce and verify `entry_hash`.
#[must_use]
pub fn audit_hmac_hex(key: &[u8; 32], msg: &str) -> String {
    soma_infra::crypto::hmac_sha256_hex(key, msg.as_bytes())
}

/// Unwrap `wrapped_dek` under `old_kek` and re-wrap under `new_kek`.
///
/// The bare DEK is zeroized immediately after re-wrap. This never touches
/// secret plaintext — it is the primitive a future `soma migrate rekey` sweep
/// will call row-by-row.
///
/// # Errors
///
/// - [`Error::Unwrap`] — `old_kek` is wrong or `wrapped_dek` is corrupted
/// - [`Error::Wrap`] — AES-KW wrap under `new_kek` failed (should not occur)
pub fn rewrap_dek(
    old_kek: &TenantKek,
    new_kek: &TenantKek,
    wrapped_dek: &[u8],
) -> Result<Vec<u8>> {
    let old_kek_obj: aes_kw::KekAes256 = (*old_kek.bytes()).into();
    let mut dek_vec = old_kek_obj
        .unwrap_vec(wrapped_dek)
        .map_err(|_| Error::Unwrap)?;

    let new_kek_obj: aes_kw::KekAes256 = (*new_kek.bytes()).into();
    let result = new_kek_obj.wrap_vec(&dek_vec).map_err(|_| {
        dek_vec.zeroize();
        Error::Wrap
    });

    dek_vec.zeroize();
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn master_a() -> MasterKek {
        MasterKek::from_hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
            .unwrap()
    }

    fn master_b() -> MasterKek {
        MasterKek::from_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
            .unwrap()
    }

    fn test_tenant() -> Uuid {
        Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffffffffffff").unwrap()
    }

    fn kek_a() -> TenantKek {
        master_a().derive_tenant_kek(test_tenant())
    }

    fn kek_b() -> TenantKek {
        master_b().derive_tenant_kek(test_tenant())
    }

    fn sid() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn do_encrypt(kek: &TenantKek) -> Sealed {
        let mut s = encrypt(kek, sid(), 1, b"super secret value").expect("encrypt");
        s.seal_key_id = "sw:test".into();
        s
    }

    #[test]
    fn round_trip() {
        let kek = kek_a();
        let plaintext = b"super secret value";
        let sealed = do_encrypt(&kek);
        let got = decrypt(&kek, &sealed).expect("decrypt");
        assert_eq!(got.as_slice(), plaintext);
    }

    #[test]
    fn wrong_aad_fails() {
        let kek = kek_a();
        let sealed = do_encrypt(&kek);

        // decrypt_checked with wrong version returns AadMismatch
        let err = decrypt_checked(&kek, &sealed, sid(), 2).unwrap_err();
        assert!(matches!(err, Error::AadMismatch), "unexpected: {err:?}");

        // Mutating aad directly causes GCM auth failure
        let mut bad = sealed.clone();
        bad.aad[0] ^= 0xff;
        let err2 = decrypt(&kek, &bad).unwrap_err();
        assert!(matches!(err2, Error::Decrypt), "unexpected: {err2:?}");
    }

    #[test]
    fn tamper_fails() {
        let kek = kek_a();
        let mut sealed = do_encrypt(&kek);
        sealed.ciphertext[0] ^= 0x01;
        let err = decrypt(&kek, &sealed).unwrap_err();
        assert!(matches!(err, Error::Decrypt), "unexpected: {err:?}");
    }

    #[test]
    fn wrong_kek_fails() {
        let sealed = do_encrypt(&kek_a());
        let err = decrypt(&kek_b(), &sealed).unwrap_err();
        assert!(matches!(err, Error::Unwrap), "unexpected: {err:?}");
    }

    #[test]
    fn rewrap_round_trip() {
        let plaintext = b"rewrap me";
        let mut sealed_a = encrypt(&kek_a(), sid(), 1, plaintext).expect("encrypt under A");
        sealed_a.seal_key_id = "sw:test-a".into();
        let got_a = decrypt(&kek_a(), &sealed_a).expect("decrypt under A");
        assert_eq!(got_a.as_slice(), plaintext);

        let new_wrapped =
            rewrap_dek(&kek_a(), &kek_b(), &sealed_a.wrapped_dek).expect("rewrap A→B");

        // Decrypt under B with the rewrapped DEK (ciphertext unchanged)
        let sealed_b = Sealed {
            wrapped_dek: new_wrapped.clone(),
            seal_provider: SealProvider::Software,
            seal_key_id: "sw:test-b".into(),
            ..sealed_a.clone()
        };
        let got = decrypt(&kek_b(), &sealed_b).expect("decrypt under B");
        assert_eq!(got.as_slice(), plaintext);

        // Same rewrapped DEK under A must fail
        let sealed_bad = Sealed {
            wrapped_dek: new_wrapped,
            ..sealed_a
        };
        let err = decrypt(&kek_a(), &sealed_bad).unwrap_err();
        assert!(matches!(err, Error::Unwrap), "unexpected: {err:?}");
    }

    #[test]
    fn kek_hex_parse() {
        // Too short
        assert!(matches!(
            MasterKek::from_hex("deadbeef"),
            Err(Error::KeyFormat(_))
        ));
        // Non-hex chars
        assert!(matches!(
            MasterKek::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            Err(Error::KeyFormat(_))
        ));
        // Valid 64 hex chars
        assert!(MasterKek::from_hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        )
        .is_ok());
    }

    #[test]
    fn seal_provider_roundtrip() {
        use std::str::FromStr;
        for s in ["software", "aws_kms", "gcp_kms", "azure_kms"] {
            let p = SealProvider::from_str(s).unwrap();
            assert_eq!(p.as_str(), s);
        }
        assert!(SealProvider::from_str("unknown").is_err());
    }

    #[test]
    fn tenant_kek_differs_per_tenant() {
        let master = master_a();
        let t1 = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let t2 = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let kek1 = master.derive_tenant_kek(t1);
        let kek2 = master.derive_tenant_kek(t2);
        // Keys for different tenants must differ
        assert_ne!(kek1.bytes(), kek2.bytes());
    }

    #[test]
    fn tenant_kek_is_deterministic() {
        let master = master_a();
        let tid = test_tenant();
        let k1 = master.derive_tenant_kek(tid);
        let k2 = master.derive_tenant_kek(tid);
        assert_eq!(k1.bytes(), k2.bytes());
    }

    #[test]
    fn master_fingerprint() {
        let kek = master_a();
        let fp = kek.fingerprint();
        assert!(fp.starts_with("sw:"), "fingerprint: {fp}");
        assert_eq!(fp.len(), 3 + 16); // "sw:" + 8 hex bytes
    }
}
