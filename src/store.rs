//! Durable state store for dynamically registered OAuth clients and hashed token grants.

use crate::crypto::random_token_b64;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE_VERSION: u32 = 1;
const MAX_STATE_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredClient {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_sha256: Option<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessTokenRecord {
    pub token_sha256: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshTokenRecord {
    pub token_sha256: String,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_until: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    pub grant_id: String,
    pub client_id: String,
    pub pool_slot: usize,
    pub scopes: Vec<String>,
    pub resource: String,
    pub access_tokens: Vec<AccessTokenRecord>,
    pub refresh_tokens: Vec<RefreshTokenRecord>,
}

impl GrantRecord {
    /// Prunes expired token digests while keeping rotated refresh tokens until `expires_at`
    /// so post-grace replay revokes the whole grant under RFC 9700.
    pub fn prune_expired(&mut self, now: u64) -> (bool, bool) {
        let prev_at = self.access_tokens.len();
        let prev_rt = self.refresh_tokens.len();
        self.access_tokens.retain(|at| at.expires_at > now);
        self.refresh_tokens.retain(|rt| rt.expires_at > now);
        let changed = self.access_tokens.len() != prev_at || self.refresh_tokens.len() != prev_rt;
        let has_usable = !self.access_tokens.is_empty()
            || self
                .refresh_tokens
                .iter()
                .any(|rt| rt.grace_until.is_none_or(|gu| gu >= now));
        (changed, has_usable)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersistedState {
    pub version: u32,
    #[serde(default)]
    pub clients: Vec<RegisteredClient>,
    #[serde(default)]
    pub grants: Vec<GrantRecord>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self::empty()
    }
}

impl PersistedState {
    pub fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            clients: Vec::new(),
            grants: Vec::new(),
        }
    }

    pub fn prune_expired(&mut self, now: u64) -> bool {
        let mut mutated = false;
        self.grants.retain_mut(|grant| {
            let (changed, keep) = grant.prune_expired(now);
            if changed || !keep {
                mutated = true;
            }
            keep
        });
        mutated
    }
}

#[derive(Clone, Debug)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn open(path: PathBuf, now: u64) -> Result<(Self, PersistedState), String> {
        let store = Self { path };
        match fs::symlink_metadata(&store.path) {
            Ok(meta) => {
                validate_existing_metadata(&store.path, &meta)?;
                let mut state = read_state_file(&store.path)?;
                if state.prune_expired(now) {
                    store.save(&state)?;
                }
                Ok((store, state))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let empty = PersistedState::empty();
                store.save(&empty)?;
                Ok((store, empty))
            }
            Err(err) => Err(format!(
                "cannot inspect state_path {}: {err}",
                store.path.display()
            )),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self, state: &PersistedState) -> Result<(), String> {
        let parent = parent_dir(&self.path);
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create state directory {}: {e}", parent.display()))?;

        validate_target_path(&self.path)?;

        let payload = serde_json::to_vec_pretty(state)
            .map_err(|e| format!("cannot serialize OAuth state: {e}"))?;
        let base_name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("state_path {} has invalid file name", self.path.display()))?;
        let suffix = random_token_b64(12)?;
        let tmp_path = parent.join(format!(".{base_name}.tmp.{suffix}"));

        let write_res = write_temp_file(&tmp_path, &payload).and_then(|()| {
            validate_target_path(&self.path)?;
            fs::rename(&tmp_path, &self.path).map_err(|e| {
                format!(
                    "cannot atomically replace state file {}: {e}",
                    self.path.display()
                )
            })
        });

        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        sync_directory(parent)?;
        Ok(())
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn validate_target_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => validate_existing_metadata(path, &meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "cannot inspect state_path {}: {err}",
            path.display()
        )),
    }
}

fn validate_existing_metadata(path: &Path, meta: &fs::Metadata) -> Result<(), String> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(format!(
            "state_path {} must not be a symbolic link",
            path.display()
        ));
    }
    if ft.is_dir() || !ft.is_file() {
        return Err(format!(
            "state_path {} must be a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(format!(
                "state_path {} must not have multiple hard links",
                path.display()
            ));
        }
    }
    Ok(())
}

fn read_state_file(path: &Path) -> Result<PersistedState, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("cannot open state file {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat open state file {}: {e}", path.display()))?;
    validate_existing_metadata(path, &meta)?;
    if meta.len() > MAX_STATE_FILE_BYTES {
        return Err(format!(
            "state file {} exceeds maximum size limit",
            path.display()
        ));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    file.read_to_end(&mut buf)
        .map_err(|e| format!("cannot read state file {}: {e}", path.display()))?;
    let parsed: PersistedState = serde_json::from_slice(&buf)
        .map_err(|e| format!("invalid state JSON in {}: {e}", path.display()))?;
    if parsed.version != STATE_VERSION {
        return Err(format!(
            "unsupported state version {} in {}",
            parsed.version,
            path.display()
        ));
    }
    Ok(parsed)
}

fn write_temp_file(tmp_path: &Path, payload: &[u8]) -> Result<(), String> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW);
    }
    let mut file = opts.open(tmp_path).map_err(|e| {
        format!(
            "cannot create temporary state file {}: {e}",
            tmp_path.display()
        )
    })?;
    file.write_all(payload).map_err(|e| {
        format!(
            "cannot write temporary state file {}: {e}",
            tmp_path.display()
        )
    })?;
    file.sync_all().map_err(|e| {
        format!(
            "cannot sync temporary state file {}: {e}",
            tmp_path.display()
        )
    })?;
    Ok(())
}

fn sync_directory(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(dir)
            .map_err(|e| format!("cannot open state directory {}: {e}", dir.display()))?;
        dir_file
            .sync_all()
            .map_err(|e| format!("cannot sync state directory {}: {e}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        let dir_file = std::fs::File::open(dir)
            .map_err(|e| format!("cannot open state directory {}: {e}", dir.display()))?;
        let _ = dir_file.sync_all();
    }
    Ok(())
}
