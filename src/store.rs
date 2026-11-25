//! Durable state store for dynamically registered OAuth clients and hashed token grants.

use crate::crypto::{random_token_b64, zeroize_bytes};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE_VERSION: u32 = 1;
pub const MAX_GRACE_REFRESHES: usize = 16;
const MAX_STATE_FILE_BYTES: u64 = 64 * 1024 * 1024;

static MONOTONIC_UNIX_FLOOR: AtomicU64 = AtomicU64::new(0);

struct ZeroizingBuf(Vec<u8>);

impl ZeroizingBuf {
    fn with_capacity(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Drop for ZeroizingBuf {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
        self.0.clear();
    }
}

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

        let approx_cap = 256usize
            .saturating_add(state.clients.len().saturating_mul(384))
            .saturating_add(state.grants.len().saturating_mul(512));
        let mut payload = ZeroizingBuf::with_capacity(approx_cap);
        serde_json::to_writer_pretty(payload.as_mut_vec(), state)
            .map_err(|e| format!("cannot serialize OAuth state: {e}"))?;
        if payload.as_slice().len() as u64 > MAX_STATE_FILE_BYTES {
            return Err(format!(
                "serialized OAuth state exceeds maximum size limit ({MAX_STATE_FILE_BYTES} bytes)"
            ));
        }
        let base_name = base_file_name(&self.path)?;
        let suffix = random_token_b64(12)?;
        let tmp_path = parent.join(format!(".{base_name}.tmp.{suffix}"));

        let write_res = write_temp_file(&tmp_path, payload.as_slice()).and_then(|()| {
            validate_target_path(&self.path)?;
            replace_state_file(&tmp_path, &self.path).map_err(|e| {
                format!(
                    "cannot atomically replace state file {}: {e}",
                    self.path.display()
                )
            })
        });
        drop(payload);

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

#[cfg(any(windows, test))]
fn build_owner_only_sddl(user_sid: &str, inherit: bool) -> String {
    let flags = if inherit { "OICI" } else { "" };
    let mut sddl = format!("D:P(A;{flags};GA;;;{user_sid})");
    if !user_sid.eq_ignore_ascii_case("S-1-5-18") {
        sddl.push_str(&format!("(A;{flags};GA;;;SY)"));
    }
    if !user_sid.eq_ignore_ascii_case("S-1-5-32-544") {
        sddl.push_str(&format!("(A;{flags};GA;;;BA)"));
    }
    sddl
}

fn create_state_dir(parent: &Path) -> Result<(), String> {
    #[cfg(windows)]
    let missing_dirs = windows_platform::collect_missing_ancestors(parent);
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|e| format!("cannot create state directory {}: {e}", parent.display()))?;
    #[cfg(windows)]
    for dir in missing_dirs.iter().rev() {
        windows_platform::apply_owner_only_dacl(dir, true).map_err(|e| {
            format!(
                "cannot set owner-only DACL on state directory {}: {e}",
                dir.display()
            )
        })?;
    }
    Ok(())
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
    #[cfg(unix)]
    {
        fs::rename(tmp_path, target)
    }
    #[cfg(windows)]
    {
        windows_platform::replace_file_with_retry(tmp_path, target)
    }
}

fn validate_target_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            validate_existing_metadata(path, &meta)?;
            #[cfg(windows)]
            windows_platform::validate_existing_path_links(path)?;
            Ok(())
        }
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

fn open_state_for_read(path: &Path) -> Result<fs::File, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path)
        .map_err(|e| format!("cannot open state file {}: {e}", path.display()))
}

fn read_state_file(path: &Path) -> Result<PersistedState, String> {
    let file = open_state_for_read(path)?;
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
    #[cfg(windows)]
    {
        windows_platform::verify_and_enforce_state_file_security(&file, path)?;
    }
    if meta.len() > MAX_STATE_FILE_BYTES {
        return Err(format!(
            "state file {} exceeds maximum size limit",
            path.display()
        ));
    }
    let mut buf =
        ZeroizingBuf::with_capacity((meta.len() as usize).min(MAX_STATE_FILE_BYTES as usize));
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(buf.as_mut_vec())
        .map_err(|e| format!("cannot read state file {}: {e}", path.display()))?;
    if buf.as_slice().len() as u64 > MAX_STATE_FILE_BYTES {
        return Err(format!(
            "state file {} exceeds maximum size limit",
            path.display()
        ));
    }
    let parsed: Result<PersistedState, _> = serde_json::from_slice(buf.as_slice());
    drop(buf);
    let parsed = parsed.map_err(|e| format!("invalid state JSON in {}: {e}", path.display()))?;
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
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(tmp_path)
            .map_err(|e| {
                format!(
                    "cannot create temporary state file {}: {e}",
                    tmp_path.display()
                )
            })?
    };

    #[cfg(windows)]
    let mut file = windows_platform::create_private_temp_file(tmp_path).map_err(|e| {
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
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
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

#[cfg(windows)]
mod windows_platform {
    use super::build_owner_only_sddl;
    use std::ffi::{OsStr, c_void};
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE,
        HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid,
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING,
        READ_CONTROL, WRITE_DAC,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const ACCESS_ALLOWED_ACE_KIND: u8 = 0;
    const SID_HEADER_BYTES: usize = 8;
    const SID_MAX_SUB_AUTHORITIES: usize = 15;

    struct ProcessUserSid {
        buffer: Vec<usize>,
        sddl_sid: String,
    }

    impl ProcessUserSid {
        fn current() -> io::Result<Self> {
            let mut token: HANDLE = std::ptr::null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let res = Self::from_token(token);
            unsafe { CloseHandle(token) };
            res
        }

        fn from_token(token: HANDLE) -> io::Result<Self> {
            let mut needed = 0u32;
            unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
            if needed == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
            let length = (buffer.len() * std::mem::size_of::<usize>()) as u32;
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut needed,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
            if user.User.Sid.is_null() || unsafe { IsValidSid(user.User.Sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "process token returned invalid user SID",
                ));
            }
            let mut text: *mut u16 = std::ptr::null_mut();
            if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0usize;
            unsafe {
                while *text.add(len) != 0 {
                    len += 1;
                }
            }
            let sddl_sid =
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
            unsafe { LocalFree(text as HLOCAL) };
            Ok(Self { buffer, sddl_sid })
        }

        fn psid(&self) -> PSID {
            let user = unsafe { &*self.buffer.as_ptr().cast::<TOKEN_USER>() };
            user.User.Sid
        }
    }

    pub(super) struct OwnedDescriptor(pub(super) PSECURITY_DESCRIPTOR);

    impl Drop for OwnedDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0 as HLOCAL) };
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum HandleSecurityState {
        StrictProtected,
        NeedsTightening,
        UntrustedOwner,
    }

    fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
        let mut out: Vec<u16> = s.encode_wide().collect();
        if out.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        out.push(0);
        Ok(out)
    }

    pub(super) fn descriptor_from_sddl(sddl: &str) -> io::Result<OwnedDescriptor> {
        let w = wide(OsStr::new(sddl))?;
        let mut desc: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut desc,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedDescriptor(desc))
    }

    fn owner_only_descriptor(user_sid: &str, inherit: bool) -> io::Result<OwnedDescriptor> {
        let sddl = build_owner_only_sddl(user_sid, inherit);
        descriptor_from_sddl(&sddl)
    }

    fn extract_dacl(desc: &OwnedDescriptor) -> io::Result<*mut ACL> {
        let mut present = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorDacl(desc.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
            || present == 0
            || dacl.is_null()
        {
            return Err(io::Error::last_os_error());
        }
        Ok(dacl)
    }

    pub fn collect_missing_ancestors(parent: &Path) -> Vec<PathBuf> {
        let mut missing = Vec::new();
        for ancestor in parent.ancestors() {
            if ancestor.as_os_str().is_empty() || ancestor.exists() {
                break;
            }
            missing.push(ancestor.to_path_buf());
        }
        missing
    }

    pub fn apply_owner_only_dacl(path: &Path, inherit: bool) -> io::Result<()> {
        let user = ProcessUserSid::current()?;
        let desc = owner_only_descriptor(&user.sddl_sid, inherit)?;
        let dacl = extract_dacl(&desc)?;
        let wpath = wide(path.as_os_str())?;
        let status = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn query_handle_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    fn validate_handle_info(path: &Path, info: &BY_HANDLE_FILE_INFORMATION) -> Result<(), String> {
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(format!(
                "state_path {} must not be a reparse point",
                path.display()
            ));
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(format!(
                "state_path {} must be a regular file",
                path.display()
            ));
        }
        if info.nNumberOfLinks != 1 {
            return Err(format!(
                "state_path {} must not have multiple hard links",
                path.display()
            ));
        }
        Ok(())
    }

    pub fn validate_existing_path_links(path: &Path) -> Result<(), String> {
        let wpath = wide(path.as_os_str())
            .map_err(|e| format!("cannot inspect state_path {}: {e}", path.display()))?;
        let handle = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(format!(
                "cannot inspect state_path {}: {err}",
                path.display()
            ));
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let info = query_handle_info(&file)
            .map_err(|e| format!("cannot inspect state_path {}: {e}", path.display()))?;
        validate_handle_info(path, &info)
    }

    fn is_trusted_sid(candidate: PSID, current_user_sid: PSID) -> bool {
        if candidate.is_null() || unsafe { IsValidSid(candidate) } == 0 {
            return false;
        }
        unsafe {
            EqualSid(candidate, current_user_sid) != 0
                || IsWellKnownSid(candidate, WinLocalSystemSid) != 0
                || IsWellKnownSid(candidate, WinBuiltinAdministratorsSid) != 0
        }
    }

    pub(super) fn is_strict_protected_dacl(
        sd: PSECURITY_DESCRIPTOR,
        dacl: *const ACL,
        current_user_sid: PSID,
    ) -> io::Result<bool> {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if (control & SE_DACL_PROTECTED) == 0 || dacl.is_null() {
            return Ok(false);
        }
        let mut acl_size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut acl_size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if acl_size.AceCount == 0 {
            return Ok(false);
        }
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        for ace_index in 0..acl_size.AceCount {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            if unsafe { GetAce(dacl, ace_index, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
                return Err(io::Error::last_os_error());
            }
            let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
            if header.AceType != ACCESS_ALLOWED_ACE_KIND
                || (header.AceSize as usize) < sid_offset + SID_HEADER_BYTES
            {
                return Ok(false);
            }
            let allow_ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
            let trustee_sid = std::ptr::addr_of!(allow_ace.SidStart) as PSID;
            let sub_auth_count = unsafe { *((trustee_sid as *const u8).add(1)) } as usize;
            let expected_sid_bytes = SID_HEADER_BYTES + 4 * sub_auth_count;
            if sub_auth_count > SID_MAX_SUB_AUTHORITIES
                || (header.AceSize as usize) < sid_offset + expected_sid_bytes
            {
                return Ok(false);
            }
            if !is_trusted_sid(trustee_sid, current_user_sid) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn inspect_handle_security(
        handle: HANDLE,
        current_user_sid: PSID,
    ) -> io::Result<HandleSecurityState> {
        let mut owner_sid: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut raw_sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut raw_sd,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let sd = OwnedDescriptor(raw_sd);
        if !is_trusted_sid(owner_sid, current_user_sid) {
            return Ok(HandleSecurityState::UntrustedOwner);
        }
        if is_strict_protected_dacl(sd.0, dacl, current_user_sid)? {
            Ok(HandleSecurityState::StrictProtected)
        } else {
            Ok(HandleSecurityState::NeedsTightening)
        }
    }

    fn same_file_identity(a: &BY_HANDLE_FILE_INFORMATION, b: &BY_HANDLE_FILE_INFORMATION) -> bool {
        a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
            && a.nFileIndexHigh == b.nFileIndexHigh
            && a.nFileIndexLow == b.nFileIndexLow
    }

    fn tighten_dacl_for_same_file(
        path: &Path,
        expected: &BY_HANDLE_FILE_INFORMATION,
        user_sid_sddl: &str,
    ) -> io::Result<()> {
        let desc = owner_only_descriptor(user_sid_sddl, false)?;
        let dacl = extract_dacl(&desc)?;
        let wpath = wide(path.as_os_str())?;
        let handle = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let dac_file = unsafe { File::from_raw_handle(handle) };
        let actual = query_handle_info(&dac_file)?;
        if !same_file_identity(expected, &actual)
            || (actual.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || actual.nNumberOfLinks != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "state file changed during DACL enforcement",
            ));
        }
        let status = unsafe {
            SetSecurityInfo(
                dac_file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub fn verify_and_enforce_state_file_security(file: &File, path: &Path) -> Result<(), String> {
        let info = query_handle_info(file)
            .map_err(|e| format!("cannot inspect open state file {}: {e}", path.display()))?;
        validate_handle_info(path, &info)?;

        let user = ProcessUserSid::current().map_err(|e| {
            format!(
                "cannot query process user SID for state file {}: {e}",
                path.display()
            )
        })?;
        match inspect_handle_security(file.as_raw_handle(), user.psid()).map_err(|e| {
            format!(
                "cannot inspect security descriptor on {}: {e}",
                path.display()
            )
        })? {
            HandleSecurityState::StrictProtected => Ok(()),
            HandleSecurityState::UntrustedOwner => Err(format!(
                "state file {} is owned by an untrusted principal",
                path.display()
            )),
            HandleSecurityState::NeedsTightening => {
                tighten_dacl_for_same_file(path, &info, &user.sddl_sid).map_err(|e| {
                    format!(
                        "cannot enforce protected owner-only DACL on state file {}: {e}",
                        path.display()
                    )
                })?;
                let recheck =
                    inspect_handle_security(file.as_raw_handle(), user.psid()).map_err(|e| {
                        format!(
                            "cannot re-verify security descriptor on state file {}: {e}",
                            path.display()
                        )
                    })?;
                if recheck != HandleSecurityState::StrictProtected {
                    return Err(format!(
                        "state file {} failed protected DACL verification after tightening",
                        path.display()
                    ));
                }
                Ok(())
            }
        }
    }

    pub fn create_private_temp_file(path: &Path) -> io::Result<File> {
        let user = ProcessUserSid::current()?;
        let desc = owner_only_descriptor(&user.sddl_sid, false)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: desc.0,
            bInheritHandle: 0,
        };
        let name = wide(path.as_os_str())?;
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let info = query_handle_info(&file)?;
        if (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "temporary state file is not a regular file",
            ));
        }
        if info.nNumberOfLinks != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "temporary state file must not have multiple hard links",
            ));
        }
        Ok(file)
    }

    pub fn replace_file_with_retry(from: &Path, to: &Path) -> io::Result<()> {
        let from_w = wide(from.as_os_str())?;
        let to_w = wide(to.as_os_str())?;
        const MAX_RETRIES: usize = 5;
        for attempt in 0..=MAX_RETRIES {
            let ok = unsafe {
                MoveFileExW(
                    from_w.as_ptr(),
                    to_w.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if ok != 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if attempt < MAX_RETRIES
                && matches!(
                    err.raw_os_error(),
                    Some(code)
                        if code == ERROR_ACCESS_DENIED as i32
                            || code == ERROR_SHARING_VIOLATION as i32
                )
            {
                std::thread::sleep(Duration::from_millis(10u64 << attempt));
                continue;
            }
            return Err(err);
        }
        unreachable!()
    }

    #[cfg(test)]
    pub(super) fn sddl_satisfies_strict_dacl(sddl: &str) -> io::Result<bool> {
        let user = ProcessUserSid::current()?;
        let desc = descriptor_from_sddl(sddl)?;
        let mut present = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorDacl(desc.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let dacl_ptr = if present == 0 {
            std::ptr::null()
        } else {
            dacl.cast_const()
        };
        is_strict_protected_dacl(desc.0, dacl_ptr, user.psid())
    }

    #[cfg(test)]
    pub(super) fn current_sddl_sid() -> io::Result<String> {
        Ok(ProcessUserSid::current()?.sddl_sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state(now: u64) -> PersistedState {
        PersistedState {
            version: STATE_VERSION,
            clients: vec![RegisteredClient {
                client_id: "cli_test_1".to_owned(),
                client_name: Some("Test CLI".to_owned()),
                redirect_uris: vec!["http://127.0.0.1:8765/cb".to_owned()],
                grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
                response_types: vec!["code".to_owned()],
                token_endpoint_auth_method: "none".to_owned(),
                client_secret_sha256: None,
                allowed_scopes: Some(vec!["mcp".to_owned()]),
                issued_at: now,
            }],
            grants: vec![GrantRecord {
                grant_id: "grt_test_1".to_owned(),
                client_id: "cli_test_1".to_owned(),
                pool_slot: 0,
                scopes: vec!["mcp".to_owned()],
                resource: "https://mcp.example.com/mcp".to_owned(),
                issued_at: now,
                max_expires_at: now + 7200,
                family_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                current_gen: 1,
                current_refresh: Some(RefreshTokenRecord {
                    r#gen: 1,
                    token_sha256: "rt_hash_live".to_owned(),
                    expires_at: now + 3600,
                }),
                grace_refreshes: vec![GraceRefreshRecord {
                    r#gen: 0,
                    token_sha256: "rt_hash_expired_grace".to_owned(),
                    grace_until: now.saturating_sub(1),
                }],
                access_tokens: vec![
                    AccessTokenRecord {
                        token_sha256: "at_hash_live".to_owned(),
                        expires_at: now + 600,
                        scopes: vec!["mcp".to_owned()],
                    },
                    AccessTokenRecord {
                        token_sha256: "at_hash_expired".to_owned(),
                        expires_at: now,
                        scopes: vec!["mcp".to_owned()],
                    },
                ],
                consumed_code_sha256: Some(("code_hash_expired".to_owned(), now)),
            }],
        }
    }

    #[test]
    fn open_cleans_stale_tmp_and_enforces_private_permissions() {
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
        #[cfg(windows)]
        {
            let file = open_state_for_read(&nested).unwrap();
            windows_platform::verify_and_enforce_state_file_security(&file, &nested).unwrap();
        }

        let t1 = unix_now();
        let t2 = unix_now();
        assert!(t2 >= t1);
    }

    #[test]
    fn save_open_roundtrip_prunes_expired_and_rejects_malformed_inputs() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested/deep/state.json");
        let now = 1_760_000_000;
        let (store, empty) = StateStore::open(path.clone(), now).unwrap();
        assert_eq!(empty, PersistedState::empty());

        let state = sample_state(now);
        store.save(&state).unwrap();

        let (_, loaded) = StateStore::open(path.clone(), now).unwrap();
        assert_eq!(loaded.clients, state.clients);
        assert_eq!(loaded.grants.len(), 1);
        assert_eq!(
            loaded.grants[0].family_key_b64,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(loaded.grants[0].access_tokens.len(), 1);
        assert!(loaded.grants[0].grace_refreshes.is_empty());
        assert!(loaded.grants[0].consumed_code_sha256.is_none());

        // Unknown fields must fail closed while still zeroizing read buffers.
        fs::write(
            &path,
            r#"{"version":1,"clients":[],"grants":[],"unexpected":1}"#,
        )
        .unwrap();
        let unknown_err = StateStore::open(path.clone(), now).unwrap_err();
        assert!(
            unknown_err.contains("invalid state JSON"),
            "unexpected error: {unknown_err}"
        );

        // Truncated JSON must fail closed.
        fs::write(
            &path,
            br#"{"version":1,"grants":[{"family_key_b64":"secret"#,
        )
        .unwrap();
        let corrupt_err = StateStore::open(path.clone(), now).unwrap_err();
        assert!(
            corrupt_err.contains("invalid state JSON"),
            "unexpected error: {corrupt_err}"
        );

        // Unsupported schema version must fail closed.
        fs::write(&path, r#"{"version":99,"clients":[],"grants":[]}"#).unwrap();
        let ver_err = StateStore::open(path, now).unwrap_err();
        assert!(
            ver_err.contains("unsupported state version"),
            "unexpected error: {ver_err}"
        );
    }

    #[test]
    fn zeroizing_buf_clears_sensitive_bytes_before_release() {
        let mut buf = ZeroizingBuf::with_capacity(64);
        buf.as_mut_vec()
            .extend_from_slice(b"{\"family_key_b64\":\"super_secret_key_material\"}");
        assert!(!buf.as_slice().is_empty());
        zeroize_bytes(&mut buf.0);
        assert!(buf.0.iter().all(|&b| b == 0));
        drop(buf);
    }

    #[test]
    fn owner_only_sddl_grants_only_user_system_and_admins() {
        let user_sddl = build_owner_only_sddl("S-1-5-21-100-200-300-1001", false);
        assert_eq!(
            user_sddl,
            "D:P(A;;GA;;;S-1-5-21-100-200-300-1001)(A;;GA;;;SY)(A;;GA;;;BA)"
        );

        let dir_sddl = build_owner_only_sddl("S-1-5-21-100-200-300-1001", true);
        assert_eq!(
            dir_sddl,
            "D:P(A;OICI;GA;;;S-1-5-21-100-200-300-1001)(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"
        );

        let system_sddl = build_owner_only_sddl("S-1-5-18", false);
        assert_eq!(system_sddl, "D:P(A;;GA;;;S-1-5-18)(A;;GA;;;BA)");

        let admin_sddl = build_owner_only_sddl("S-1-5-32-544", true);
        assert_eq!(admin_sddl, "D:P(A;OICI;GA;;;S-1-5-32-544)(A;OICI;GA;;;SY)");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_multiple_hard_links() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let real = dir.path().join("real.json");
        fs::write(&real, r#"{"version":1,"clients":[],"grants":[]}"#).unwrap();

        let sym = dir.path().join("symlink.json");
        symlink(&real, &sym).unwrap();
        let sym_err = StateStore::open(sym, unix_now()).unwrap_err();
        assert!(
            sym_err.contains("symbolic link"),
            "unexpected error: {sym_err}"
        );

        let hard_a = dir.path().join("hard_a.json");
        let hard_b = dir.path().join("hard_b.json");
        let (store, _) = StateStore::open(hard_a.clone(), unix_now()).unwrap();
        fs::hard_link(&hard_a, &hard_b).unwrap();

        let open_err = StateStore::open(hard_a, unix_now()).unwrap_err();
        assert!(
            open_err.contains("hard links"),
            "unexpected error: {open_err}"
        );
        let save_err = store.save(&PersistedState::empty()).unwrap_err();
        assert!(
            save_err.contains("hard links"),
            "unexpected error: {save_err}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_hard_links_and_validates_dacl_descriptors() {
        let sid = windows_platform::current_sddl_sid().unwrap();
        let strict = build_owner_only_sddl(&sid, false);
        assert!(windows_platform::sddl_satisfies_strict_dacl(&strict).unwrap());

        // Unprotected DACL (missing P flag) must be flagged as non-strict.
        let unprotected = format!("D:(A;;GA;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)");
        assert!(!windows_platform::sddl_satisfies_strict_dacl(&unprotected).unwrap());

        // Protected DACL granting read access to Everyone (WD) must be rejected as non-strict.
        let world_readable = format!("D:P(A;;GA;;;{sid})(A;;FR;;;WD)");
        assert!(!windows_platform::sddl_satisfies_strict_dacl(&world_readable).unwrap());

        // Seeded state file with inherited ACL must be tightened on open, and hard links rejected.
        let dir = tempfile::TempDir::new().unwrap();
        let seeded = dir.path().join("seeded.json");
        fs::write(&seeded, r#"{"version":1,"clients":[],"grants":[]}"#).unwrap();
        let (store, _) = StateStore::open(seeded.clone(), unix_now()).unwrap();

        let linked = dir.path().join("linked.json");
        fs::hard_link(&seeded, &linked).unwrap();
        let open_err = StateStore::open(seeded, unix_now()).unwrap_err();
        assert!(
            open_err.contains("hard links"),
            "unexpected error: {open_err}"
        );
        let save_err = store.save(&PersistedState::empty()).unwrap_err();
        assert!(
            save_err.contains("hard links"),
            "unexpected error: {save_err}"
        );
    }
}
