//! Dual storage: File-based (primary) + OS Credential Manager (secondary).
//!
//! `auth_session.dat` holds the access/refresh tokens as an AES-256-GCM sealed
//! blob: `[0x03][nonce: 12][ciphertext || 16-byte tag]`. The key is derived from
//! a machine identifier (the registry `MachineGuid`) mixed with the per-user
//! data directory path, so sessions written on machine A can't be decrypted on
//! machine B, and sessions written by user A can't be decrypted by user B.
//!
//! Pre-1.0 SDK files used XOR+base64 obfuscation. They are migrated transparently
//! on first read — the existing data is re-sealed and written back in the new
//! format so the user doesn't need to log in again.

use super::types::{AuthSession, OAuthPendingState};
use crate::error::SdkError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use keyring::Entry;
use log::{debug, error, info, warn};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const SERVICE_NAME: &str = "SwiftTunnel";
const SESSION_KEY: &str = "auth_session";
const OAUTH_STATE_FILE: &str = "oauth_pending.json";
const AUTH_SESSION_FILE: &str = "auth_session.dat";
const REFRESH_FAILURES_FILE: &str = "refresh_failures.json";
const LEGACY_REFRESH_FAILURES_FILE: &str = "refresh_failures.txt";

/// Version tag for AES-256-GCM sealed blobs. Value is outside the printable
/// base64 alphabet so the loader can tell new-format files from the legacy
/// XOR+base64 files unambiguously.
const SESSION_VERSION_TAG: u8 = 0x03;

/// Key-derivation domain separator. Bumping this string invalidates every
/// sealed session on disk and forces re-login.
const KEY_DERIVATION_INFO: &[u8] = b"swifttunnel-auth-v3-session-key";

const AEAD_TAG_LEN: usize = 16;

/// XOR key kept ONLY for one-shot migration of pre-1.0 SDK auth_session.dat
/// files. No new files are ever written in this format.
const LEGACY_OBFUSCATION_KEY: &[u8] = b"SwiftTunnel2024AuthStorage";

/// Window during which consecutive refresh failures are aggregated. Failures
/// older than this reset the counter so transient errors days apart never
/// strand a user.
const REFRESH_FAILURE_WINDOW: chrono::Duration = chrono::Duration::hours(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshFailureRecord {
    count: u32,
    first_failure_at: DateTime<Utc>,
}

#[cfg(windows)]
fn read_machine_id() -> String {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
        if let Ok(guid) = key.get_value::<String, _>("MachineGuid") {
            return guid;
        }
    }
    String::from("swifttunnel-unknown-machine")
}

#[cfg(not(windows))]
fn read_machine_id() -> String {
    String::from("swifttunnel-dev-machine")
}

/// Derive a 32-byte AES-256 key from the machine id and a per-user bind.
fn derive_session_key(user_bind: &[u8]) -> [u8; 32] {
    let machine_id = read_machine_id();

    let mut hasher = Sha256::new();
    hasher.update(KEY_DERIVATION_INFO);
    hasher.update([0xff]);
    hasher.update(machine_id.as_bytes());
    hasher.update([0xff]);
    hasher.update(user_bind);

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Seal `plaintext` into `[0x03][12-byte nonce][ciphertext || 16-byte tag]`.
fn seal_blob(plaintext: &[u8], user_bind: &[u8]) -> Result<Vec<u8>, SdkError> {
    let key_bytes = derive_session_key(user_bind);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| SdkError::Storage("Failed to build AES-256-GCM key".to_string()))?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| SdkError::Storage("Failed to generate nonce".to_string()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| SdkError::Storage("AES-GCM seal failed".to_string()))?;

    let mut blob = Vec::with_capacity(1 + NONCE_LEN + in_out.len());
    blob.push(SESSION_VERSION_TAG);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&in_out);
    Ok(blob)
}

/// Open a sealed blob. Returns an error if truncated or AEAD tag fails.
fn open_blob(blob: &[u8], user_bind: &[u8]) -> Result<Vec<u8>, SdkError> {
    if blob.len() < 1 + NONCE_LEN + AEAD_TAG_LEN {
        return Err(SdkError::Storage("Session blob is truncated".to_string()));
    }
    if blob[0] != SESSION_VERSION_TAG {
        return Err(SdkError::Storage(format!(
            "Unexpected session version tag {:#04x}",
            blob[0]
        )));
    }

    let key_bytes = derive_session_key(user_bind);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| SdkError::Storage("Failed to build AES-256-GCM key".to_string()))?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&blob[1..1 + NONCE_LEN]);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let mut buf = blob[1 + NONCE_LEN..].to_vec();
    let plaintext_len = {
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| {
                SdkError::Storage(
                    "AES-GCM open failed (tampered or wrong user/machine)".to_string(),
                )
            })?;
        plaintext.len()
    };
    buf.truncate(plaintext_len);
    Ok(buf)
}

/// Decode a legacy XOR+base64 auth_session.dat (pre-1.0 SDK format).
fn decrypt_legacy_v1(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    let obfuscated = BASE64.decode(text.trim()).ok()?;
    Some(
        obfuscated
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ LEGACY_OBFUSCATION_KEY[i % LEGACY_OBFUSCATION_KEY.len()])
            .collect(),
    )
}

enum DecodedBlob {
    Session {
        session: Box<AuthSession>,
        /// true when the blob was in legacy format and should be re-sealed
        rewrite: bool,
    },
    Corrupt,
}

/// Secure storage for authentication credentials using dual storage strategy.
pub struct SecureStorage {
    keyring_entry: Option<Entry>,
    data_dir: PathBuf,
}

impl SecureStorage {
    pub fn new() -> Result<Self, SdkError> {
        let data_dir = dirs::data_local_dir()
            .map(|d| d.join("SwiftTunnel"))
            .ok_or_else(|| {
                SdkError::Storage("Could not determine data directory".to_string())
            })?;

        std::fs::create_dir_all(&data_dir).map_err(|e| {
            SdkError::Storage(format!("Failed to create data directory: {}", e))
        })?;

        info!("SecureStorage initialized:");
        info!("  Data directory: {}", data_dir.display());

        let keyring_entry = match Entry::new(SERVICE_NAME, SESSION_KEY) {
            Ok(entry) => {
                info!("  Keyring: Available");
                Some(entry)
            }
            Err(e) => {
                warn!("  Keyring: Not available ({}). Using file storage only.", e);
                None
            }
        };

        Ok(Self {
            keyring_entry,
            data_dir,
        })
    }

    #[cfg(test)]
    fn with_isolated_data_dir() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let data_dir = std::env::temp_dir().join(format!(
            "swifttunnel-sdk-storage-test-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        std::fs::create_dir_all(&data_dir).expect("create test data dir");
        Self {
            keyring_entry: None,
            data_dir,
        }
    }

    fn user_bind(&self) -> Vec<u8> {
        self.data_dir
            .as_os_str()
            .to_string_lossy()
            .as_bytes()
            .to_vec()
    }

    fn session_file_path(&self) -> PathBuf {
        self.data_dir.join(AUTH_SESSION_FILE)
    }

    fn encode_session(&self, session: &AuthSession) -> Result<Vec<u8>, SdkError> {
        let json = serde_json::to_vec(session)
            .map_err(|e| SdkError::Storage(format!("Failed to serialize session: {}", e)))?;
        seal_blob(&json, &self.user_bind())
    }

    fn decode_blob(&self, raw: &[u8]) -> DecodedBlob {
        if raw.is_empty() {
            return DecodedBlob::Corrupt;
        }

        if raw[0] == SESSION_VERSION_TAG {
            return match open_blob(raw, &self.user_bind()) {
                Ok(json) => match serde_json::from_slice::<AuthSession>(&json) {
                    Ok(session) => DecodedBlob::Session {
                        session: Box::new(session),
                        rewrite: false,
                    },
                    Err(e) => {
                        error!("Failed to deserialize session JSON: {}", e);
                        DecodedBlob::Corrupt
                    }
                },
                Err(e) => {
                    error!("AES-GCM open failed: {}", e);
                    DecodedBlob::Corrupt
                }
            };
        }

        // Legacy XOR+base64 path (pre-1.0 SDK).
        let Some(json) = decrypt_legacy_v1(raw) else {
            error!("Legacy session blob could not be decoded");
            return DecodedBlob::Corrupt;
        };
        match serde_json::from_slice::<AuthSession>(&json) {
            Ok(session) => DecodedBlob::Session {
                session: Box::new(session),
                rewrite: true,
            },
            Err(e) => {
                error!("Failed to deserialize legacy session JSON: {}", e);
                DecodedBlob::Corrupt
            }
        }
    }

    fn store_to_file(&self, session: &AuthSession) -> Result<(), SdkError> {
        let path = self.session_file_path();
        let blob = self.encode_session(session)?;

        std::fs::write(&path, &blob).map_err(|e| {
            error!("Failed to write session file: {}", e);
            SdkError::Storage(format!("Failed to write session file: {}", e))
        })?;

        info!(
            "Stored session to {} ({} bytes sealed)",
            path.display(),
            blob.len()
        );
        Ok(())
    }

    fn load_from_file(&self) -> Result<Option<AuthSession>, SdkError> {
        let path = self.session_file_path();
        if !path.exists() {
            info!("Session file does not exist (first run or logged out)");
            return Ok(None);
        }

        let raw = match std::fs::read(&path) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to read session file: {}", e);
                return Ok(None);
            }
        };

        match self.decode_blob(&raw) {
            DecodedBlob::Session { session, rewrite } => {
                if rewrite {
                    info!("Migrating legacy auth_session.dat to AES-GCM format");
                    if let Err(e) = self.store_to_file(&session) {
                        warn!("Failed to re-seal legacy session file: {}", e);
                    }
                }
                info!("Loaded session for user: {}", session.user.email);
                Ok(Some(*session))
            }
            DecodedBlob::Corrupt => {
                let _ = std::fs::remove_file(&path);
                Ok(None)
            }
        }
    }

    fn clear_from_file(&self) -> Result<(), SdkError> {
        let path = self.session_file_path();
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                SdkError::Storage(format!("Failed to delete session file: {}", e))
            })?;
            info!("Cleared session file");
        }
        Ok(())
    }

    /// Store session to keyring (secondary). Holds the same AES-GCM blob,
    /// base64-encoded to pass through the keyring's string API.
    fn store_to_keyring(&self, session: &AuthSession) -> Result<(), SdkError> {
        let entry = match &self.keyring_entry {
            Some(e) => e,
            None => {
                debug!("Keyring not available, skipping keyring store");
                return Ok(());
            }
        };

        let blob = self.encode_session(session)?;
        let encoded = BASE64.encode(&blob);

        match entry.set_password(&encoded) {
            Ok(_) => {
                info!("Session also stored in credential manager");
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to store in keyring (file storage still works): {}",
                    e
                );
                Ok(())
            }
        }
    }

    fn load_from_keyring(&self) -> Result<Option<AuthSession>, SdkError> {
        let entry = match &self.keyring_entry {
            Some(e) => e,
            None => return Ok(None),
        };

        let stored = match entry.get_password() {
            Ok(s) => s,
            Err(keyring::Error::NoEntry) => {
                debug!("No session in keyring");
                return Ok(None);
            }
            Err(e) => {
                warn!("Keyring read error: {:?}", e);
                return Ok(None);
            }
        };

        if let Ok(blob) = BASE64.decode(stored.trim()) {
            match self.decode_blob(&blob) {
                DecodedBlob::Session { session, .. } => return Ok(Some(*session)),
                DecodedBlob::Corrupt => {
                    // Fall through to plaintext-JSON migration path for very
                    // old pre-1.0 keyring entries that were stored as raw JSON.
                }
            }
        }

        match serde_json::from_str::<AuthSession>(&stored) {
            Ok(session) => {
                info!("Migrated legacy plaintext keyring session");
                Ok(Some(session))
            }
            Err(e) => {
                warn!("Failed to deserialize keyring session: {}", e);
                Ok(None)
            }
        }
    }

    fn clear_from_keyring(&self) -> Result<(), SdkError> {
        if let Some(entry) = &self.keyring_entry {
            match entry.delete_credential() {
                Ok(_) => info!("Cleared session from keyring"),
                Err(keyring::Error::NoEntry) => debug!("No keyring session to clear"),
                Err(e) => warn!("Failed to clear keyring session: {}", e),
            }
        }
        Ok(())
    }

    /// Store the authentication session to BOTH file and keyring.
    pub fn store_session(&self, session: &AuthSession) -> Result<(), SdkError> {
        info!("Storing auth session for {}", session.user.email);
        self.store_to_file(session)?;
        let _ = self.store_to_keyring(session);
        Ok(())
    }

    /// Load the authentication session (file first, then keyring fallback).
    pub fn load_session(&self) -> Result<Option<AuthSession>, SdkError> {
        if let Some(session) = self.load_from_file()? {
            info!("Loaded session from file storage");
            return Ok(Some(session));
        }

        info!("File storage empty, trying keyring fallback...");
        if let Some(session) = self.load_from_keyring()? {
            info!("Loaded session from keyring (migrating to file storage)");
            let _ = self.store_to_file(&session);
            let _ = self.store_to_keyring(&session);
            return Ok(Some(session));
        }

        info!("No stored session found (user needs to log in)");
        Ok(None)
    }

    /// Clear the stored session from BOTH storages (logout).
    pub fn clear_session(&self) -> Result<(), SdkError> {
        info!("Clearing auth session from all storage locations...");

        let file_result = self.clear_from_file();
        let keyring_result = self.clear_from_keyring();

        if let Err(e) = &file_result {
            error!("File clear error: {}", e);
        }
        if let Err(e) = &keyring_result {
            error!("Keyring clear error: {}", e);
        }

        info!("Auth session cleared");
        Ok(())
    }

    /// Cheap check: is there a session file on disk? May return `true` for
    /// files that won't actually decrypt. Callers MUST follow up with
    /// `load_session` before assuming the user is logged in.
    pub fn has_session(&self) -> bool {
        self.session_file_path().exists()
    }

    fn oauth_state_path(&self) -> PathBuf {
        self.data_dir.join(OAUTH_STATE_FILE)
    }

    pub fn save_oauth_state(&self, state: &OAuthPendingState) -> Result<(), SdkError> {
        let path = self.oauth_state_path();

        let json = serde_json::to_string(state).map_err(|e| {
            SdkError::Storage(format!("Failed to serialize OAuth state: {}", e))
        })?;

        std::fs::write(&path, json).map_err(|e| {
            SdkError::Storage(format!("Failed to write OAuth state: {}", e))
        })?;

        info!("Saved OAuth pending state to: {}", path.display());
        Ok(())
    }

    pub fn load_oauth_state(&self) -> Result<Option<OAuthPendingState>, SdkError> {
        let path = self.oauth_state_path();

        if !path.exists() {
            debug!("No OAuth pending state file found");
            return Ok(None);
        }

        let json = std::fs::read_to_string(&path).map_err(|e| {
            SdkError::Storage(format!("Failed to read OAuth state: {}", e))
        })?;

        let state: OAuthPendingState = serde_json::from_str(&json).map_err(|e| {
            SdkError::Storage(format!("Failed to deserialize OAuth state: {}", e))
        })?;

        info!("Loaded OAuth pending state from disk");
        Ok(Some(state))
    }

    pub fn clear_oauth_state(&self) -> Result<(), SdkError> {
        let path = self.oauth_state_path();

        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                SdkError::Storage(format!("Failed to remove OAuth state: {}", e))
            })?;
            info!("Cleared OAuth pending state file");
        }

        Ok(())
    }

    fn refresh_failures_path(&self) -> PathBuf {
        self.data_dir.join(REFRESH_FAILURES_FILE)
    }

    fn legacy_refresh_failures_path(&self) -> PathBuf {
        self.data_dir.join(LEGACY_REFRESH_FAILURES_FILE)
    }

    /// Read the persisted refresh-failure record, dropping records older than
    /// the aggregation window so transient errors days apart don't accumulate.
    fn read_refresh_record(&self) -> Option<RefreshFailureRecord> {
        let _ = std::fs::remove_file(self.legacy_refresh_failures_path());

        let path = self.refresh_failures_path();
        if !path.exists() {
            return None;
        }
        let raw = std::fs::read_to_string(&path).ok()?;
        let record: RefreshFailureRecord = serde_json::from_str(&raw).ok()?;
        if Utc::now() - record.first_failure_at > REFRESH_FAILURE_WINDOW {
            None
        } else {
            Some(record)
        }
    }

    fn write_refresh_record(&self, record: &RefreshFailureRecord) {
        let path = self.refresh_failures_path();
        match serde_json::to_string(record) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("Failed to write refresh failures record: {}", e);
                }
            }
            Err(e) => warn!("Failed to serialize refresh failures record: {}", e),
        }
    }

    /// Increment the refresh failure counter and return the new count.
    /// Failures older than `REFRESH_FAILURE_WINDOW` reset the count to 1.
    pub fn increment_refresh_failures(&self) -> u32 {
        let new_count = match self.read_refresh_record() {
            Some(mut record) => {
                record.count = record.count.saturating_add(1);
                self.write_refresh_record(&record);
                record.count
            }
            None => {
                let record = RefreshFailureRecord {
                    count: 1,
                    first_failure_at: Utc::now(),
                };
                self.write_refresh_record(&record);
                1
            }
        };
        debug!("Incremented refresh failures to {}", new_count);
        new_count
    }

    pub fn get_refresh_failures(&self) -> u32 {
        self.read_refresh_record().map(|r| r.count).unwrap_or(0)
    }

    pub fn reset_refresh_failures(&self) {
        let path = self.refresh_failures_path();
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!("Failed to remove refresh failures file: {}", e);
            } else {
                debug!("Reset refresh failures counter");
            }
        }
        let _ = std::fs::remove_file(self.legacy_refresh_failures_path());
    }
}

impl Default for SecureStorage {
    fn default() -> Self {
        Self::new().expect("Failed to create SecureStorage")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_session(suffix: &str) -> AuthSession {
        AuthSession {
            access_token: format!("test_access_token_{}", suffix),
            refresh_token: format!("test_refresh_token_{}", suffix),
            expires_at: Utc::now() + Duration::hours(1),
            user: super::super::types::UserInfo {
                id: format!("user_{}", suffix),
                email: format!("{}@example.com", suffix),
                is_tester: false,
                is_banned: false,
                banned_reason: None,
                banned_at: None,
            },
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let plaintext = b"super secret session json goes here";
        let bind = b"/some/user/path";
        let blob = seal_blob(plaintext, bind).unwrap();
        assert_eq!(blob[0], SESSION_VERSION_TAG);
        assert!(blob.len() >= 1 + NONCE_LEN + AEAD_TAG_LEN);
        let recovered = open_blob(&blob, bind).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn open_fails_with_wrong_bind() {
        let blob = seal_blob(b"payload", b"bind-a").unwrap();
        assert!(open_blob(&blob, b"bind-b").is_err());
    }

    #[test]
    fn open_fails_on_truncated_blob() {
        let blob = seal_blob(b"x", b"bind").unwrap();
        for cut in 0..(1 + NONCE_LEN + AEAD_TAG_LEN) {
            assert!(open_blob(&blob[..cut], b"bind").is_err());
        }
    }

    #[test]
    fn nonce_is_random_per_seal() {
        let a = seal_blob(b"same", b"bind").unwrap();
        let b = seal_blob(b"same", b"bind").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn encode_decode_session_roundtrip() {
        let storage = SecureStorage::with_isolated_data_dir();
        let session = make_session("rt");
        let blob = storage.encode_session(&session).unwrap();
        assert_eq!(blob[0], SESSION_VERSION_TAG);

        match storage.decode_blob(&blob) {
            DecodedBlob::Session { session: s, rewrite } => {
                assert!(!rewrite);
                assert_eq!(s.access_token, session.access_token);
                assert_eq!(s.user.email, session.user.email);
            }
            DecodedBlob::Corrupt => panic!("expected DecodedBlob::Session"),
        }
    }

    #[test]
    fn legacy_xor_blob_migrated_on_decode() {
        let storage = SecureStorage::with_isolated_data_dir();
        let session = make_session("legacy");
        let json = serde_json::to_string(&session).unwrap();
        let xored: Vec<u8> = json
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ LEGACY_OBFUSCATION_KEY[i % LEGACY_OBFUSCATION_KEY.len()])
            .collect();
        let legacy_blob = BASE64.encode(&xored).into_bytes();

        assert_ne!(legacy_blob[0], SESSION_VERSION_TAG);

        match storage.decode_blob(&legacy_blob) {
            DecodedBlob::Session { session: s, rewrite } => {
                assert!(rewrite, "legacy blob should request rewrite");
                assert_eq!(s.access_token, session.access_token);
            }
            DecodedBlob::Corrupt => panic!("expected DecodedBlob::Session (legacy)"),
        }
    }

    #[test]
    fn session_roundtrip_via_file() {
        let storage = SecureStorage::with_isolated_data_dir();

        let session = make_session("file");
        storage.store_session(&session).unwrap();
        let loaded = storage.load_session().unwrap().unwrap();
        assert_eq!(loaded.access_token, session.access_token);
        assert_eq!(loaded.user.email, session.user.email);

        storage.clear_session().unwrap();
        assert!(storage.load_session().unwrap().is_none());
    }

    #[test]
    fn legacy_file_migrated_on_load() {
        let storage = SecureStorage::with_isolated_data_dir();

        let session = make_session("migrate");
        let json = serde_json::to_string(&session).unwrap();
        let xored: Vec<u8> = json
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ LEGACY_OBFUSCATION_KEY[i % LEGACY_OBFUSCATION_KEY.len()])
            .collect();
        let legacy = BASE64.encode(&xored);
        std::fs::write(storage.session_file_path(), legacy.as_bytes()).unwrap();

        let loaded = storage.load_session().unwrap().unwrap();
        assert_eq!(loaded.access_token, session.access_token);

        // After migration the file must start with the new version tag.
        let raw = std::fs::read(storage.session_file_path()).unwrap();
        assert_eq!(raw[0], SESSION_VERSION_TAG);

        storage.clear_session().unwrap();
    }

    #[test]
    fn refresh_failures_within_window_increments() {
        let storage = SecureStorage::with_isolated_data_dir();

        assert_eq!(storage.increment_refresh_failures(), 1);
        assert_eq!(storage.increment_refresh_failures(), 2);
        assert_eq!(storage.increment_refresh_failures(), 3);
        assert_eq!(storage.get_refresh_failures(), 3);

        storage.reset_refresh_failures();
        assert_eq!(storage.get_refresh_failures(), 0);
    }

    #[test]
    fn refresh_failures_reset_after_window() {
        let storage = SecureStorage::with_isolated_data_dir();

        let stale = RefreshFailureRecord {
            count: 99,
            first_failure_at: Utc::now() - Duration::hours(2),
        };
        storage.write_refresh_record(&stale);

        assert_eq!(storage.get_refresh_failures(), 0);
        assert_eq!(storage.increment_refresh_failures(), 1);
    }

    #[test]
    fn legacy_refresh_failures_txt_deleted() {
        let storage = SecureStorage::with_isolated_data_dir();

        std::fs::write(storage.legacy_refresh_failures_path(), "42").unwrap();
        assert!(storage.legacy_refresh_failures_path().exists());

        let _ = storage.get_refresh_failures();
        assert!(!storage.legacy_refresh_failures_path().exists());

        storage.reset_refresh_failures();
    }
}
