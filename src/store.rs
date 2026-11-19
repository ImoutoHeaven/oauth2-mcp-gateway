//! Durable state store for dynamically registered OAuth clients and hashed token grants.

use crate::crypto::random_token_b64;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const STATE_VERSION: u32 = 1;
pub const MAX_GRACE_REFRESHES: usize = 16;
const MAX_STATE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const RENAME_RETRY_DELAYS_MS: [u64; 3] = [5, 15, 40];

static MONOTONIC_UNIX_FLOOR: AtomicU64 = AtomicU64::new(0);

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessTokenRecord {
    pub token_sha256: String,
    pub expires_at: u64,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshTokenRecord {
    #[serde(rename = "gen")]
    pub r#gen: u64,
    pub token_sha256: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraceRefreshRecord {
    #[serde(rename = "gen")]
    pub r#gen: u64,
    pub token_sha256: String,
    pub grace_until: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    pub grant_id: String,
    pub client_id: String,
    pub pool_slot: usize,
    pub scopes: Vec<String>,
    pub resource: String,
    pub issued_at: u64,
    pub max_expires_at: u64,
    pub family_key_b64: String,
    pub current_gen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_refresh: Option<RefreshTokenRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grace_refreshes: Vec<GraceRefreshRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access_tokens: Vec<AccessTokenRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_code_sha256: Option<(String, u64)>,
}

impl GrantRecord {
    pub fn prune_expired(&mut self, now: u64) -> (bool, bool) {
        if now >= self.max_expires_at {
            return (true, false);
        }
        let mut changed = false;

        let prev_at = self.access_tokens.len();
        self.access_tokens.retain(|at| at.expires_at > now);
        if self.access_tokens.len() != prev_at {
            changed = true;
        }

        if self
            .current_refresh
            .as_ref()
            .is_some_and(|rt| rt.expires_at <= now)
        {
            self.current_refresh = None;
            changed = true;
        }

        let prev_gr = self.grace_refreshes.len();
        self.grace_refreshes.retain(|gr| gr.grace_until >= now);
        if self.grace_refreshes.len() > MAX_GRACE_REFRESHES {
            let excess = self.grace_refreshes.len() - MAX_GRACE_REFRESHES;
            self.grace_refreshes.drain(0..excess);
        }
        if self.grace_refreshes.len() != prev_gr {
            changed = true;
        }

        if self
            .consumed_code_sha256
            .as_ref()
            .is_some_and(|(_, exp)| *exp <= now)
        {
            self.consumed_code_sha256 = None;
            changed = true;
        }

        let has_usable = !self.access_tokens.is_empty() || self.current_refresh.is_some();
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
    save_lock: std::sync::Arc<std::sync::Mutex<()>>,
}

impl StateStore {
    pub fn open(path: PathBuf, now: u64) -> Result<(Self, PersistedState), String> {
        let base_name = base_file_name(&path)?.to_owned();
        let store = Self {
            path,
            save_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
        };
        cleanup_stale_temp_files(parent_dir(&store.path), &base_name);
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

    pub fn save(&self, state: &PersistedState) -> Result<(), String> {
        let _save_guard = self
            .save_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let parent = parent_dir(&self.path);
        create_state_dir(parent)?;

        validate_target_path(&self.path)?;

        let payload = serde_json::to_vec_pretty(state)
            .map_err(|e| format!("cannot serialize OAuth state: {e}"))?;
        if payload.len() as u64 > MAX_STATE_FILE_BYTES {
            return Err(format!(
                "serialized OAuth state exceeds maximum size limit ({MAX_STATE_FILE_BYTES} bytes)"
            ));
        }
        let base_name = base_file_name(&self.path)?;
        let suffix = random_token_b64(12)?;
        let tmp_path = parent.join(format!(".{base_name}.tmp.{suffix}"));

        let write_res = write_temp_file(&tmp_path, &payload).and_then(|()| {
            validate_target_path(&self.path)?;
            replace_state_file(&tmp_path, &self.path).map_err(|e| {
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
    let raw = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    MONOTONIC_UNIX_FLOOR
        .fetch_max(raw, Ordering::Relaxed)
        .max(raw)
}

fn base_file_name(path: &Path) -> Result<&str, String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("state_path {} has invalid file name", path.display()))
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn create_state_dir(parent: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|e| format!("cannot create state directory {}: {e}", parent.display()))
}

fn cleanup_stale_temp_files(parent: &Path, base_name: &str) {
    let prefix = format!(".{base_name}.tmp.");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str().is_some_and(|s| s.starts_with(&prefix))
            && entry
                .file_type()
                .is_ok_and(|ft| ft.is_file() && !ft.is_symlink())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn replace_state_file(tmp_path: &Path, target: &Path) -> std::io::Result<()> {
    let mut attempt = 0usize;
    loop {
        match fs::rename(tmp_path, target) {
            Ok(()) => return Ok(()),
            Err(err)
                if cfg!(windows)
                    && err.kind() == std::io::ErrorKind::PermissionDenied
                    && attempt < RENAME_RETRY_DELAYS_MS.len() =>
            {
                std::thread::sleep(Duration::from_millis(RENAME_RETRY_DELAYS_MS[attempt]));
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
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
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (meta.file_attributes() & 0x400) != 0 {
            return Err(format!(
                "state_path {} must not be a reparse point",
                path.display()
            ));
        }
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
    let file = opts
        .open(path)
        .map_err(|e| format!("cannot open state file {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat open state file {}: {e}", path.display()))?;
    validate_existing_metadata(path, &meta)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o777) != 0o600 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    format!("cannot enforce 0600 on state file {}: {e}", path.display())
                })?;
        }
    }
    if meta.len() > MAX_STATE_FILE_BYTES {
        return Err(format!(
            "state file {} exceeds maximum size limit",
            path.display()
        ));
    }
    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_STATE_FILE_BYTES as usize));
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read state file {}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_STATE_FILE_BYTES {
        return Err(format!(
            "state file {} exceeds maximum size limit",
            path.display()
        ));
    }
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
        // Windows does not support File::open on directories.
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_cleans_stale_tmp_and_enforces_unix_permissions() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("sub/oauth_state.json");
        let (_, _) = StateStore::open(nested.clone(), unix_now()).unwrap();

        let parent = nested.parent().unwrap();
        let stale_tmp = parent.join(".oauth_state.json.tmp.leftover");
        fs::write(&stale_tmp, b"partial").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(parent).unwrap().permissions().mode() & 0o777,
                0o700
            );
            fs::set_permissions(&nested, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let (_, _) = StateStore::open(nested.clone(), unix_now()).unwrap();
        assert!(!stale_tmp.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let t1 = unix_now();
        let t2 = unix_now();
        assert!(t2 >= t1);
    }
}
