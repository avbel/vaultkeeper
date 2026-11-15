//! Windows rules for the private data directory (docs/solutions/windows-support.md §4.3): one
//! protected DACL and mandatory label on the directory itself, inherited by everything written
//! below it, plus the "do not index" attribute.

use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    path::Path,
    ptr,
};

use vk_win::{SecurityDescriptor, current_user_sid, sddl};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_SUCCESS, INVALID_HANDLE_VALUE,
        LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
        AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
            SetNamedSecurityInfoW, SetSecurityInfo,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl,
        IsWellKnownSid, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        SYSTEM_MANDATORY_LABEL_ACE, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS,
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        FILE_WRITE_ATTRIBUTES, FileAttributeTagInfo, FileBasicInfo, GetFileAttributesW,
        GetFileInformationByHandleEx, GetVolumeInformationByHandleW, INVALID_FILE_ATTRIBUTES,
        OPEN_EXISTING, READ_CONTROL, SetFileAttributesW, SetFileInformationByHandle, WRITE_DAC,
        WRITE_OWNER,
    },
    System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, FILE_READ_ONLY_VOLUME,
        SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        SYSTEM_MANDATORY_LABEL_NO_READ_UP, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
    },
};

use super::{Refusal, Repair};

const MEDIUM_INTEGRITY_SID: &str = "S-1-16-8192";

// These structs are a few dozen bytes, so the casts cannot truncate.
#[expect(clippy::cast_possible_truncation)]
const ATTRIBUTE_TAG_INFO_LEN: u32 = size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32;
#[expect(clippy::cast_possible_truncation)]
const BASIC_INFO_LEN: u32 = size_of::<FILE_BASIC_INFO>() as u32;
#[expect(clippy::cast_possible_truncation)]
const ACL_SIZE_LEN: u32 = size_of::<ACL_SIZE_INFORMATION>() as u32;

pub(super) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    apply_private_dacl(path)?;
    set_not_content_indexed(path)
}

/// Creates the last component only when it is missing, so an existing directory is never touched
/// before `verify_private_dir` has seen it: `SetNamedSecurityInfoW` follows reparse points and
/// would overwrite a foreign ACE the check must refuse.
pub(super) fn create_private_dir_if_missing(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
        let attributes =
            std::os::windows::fs::MetadataExt::file_attributes(&std::fs::symlink_metadata(parent)?);
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is a reparse point", parent.display()),
            ));
        }
    }
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error),
    }
    apply_private_dacl(path)?;
    set_not_content_indexed(path)
}

fn apply_private_dacl(path: &Path) -> io::Result<()> {
    let wide = wide_path(path);
    let sid = current_user_sid()?;
    let descriptor = SecurityDescriptor::from_sddl(&sddl::private_dir(&sid)?)?;

    let mut directory_acl: *mut ACL = ptr::null_mut();
    let mut directory_acl_present = 0;
    let mut defaulted = 0;
    // SAFETY: `descriptor` owns a parsed descriptor for the whole call; the out pointers are ours.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &raw mut directory_acl_present,
            &raw mut directory_acl,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if directory_acl_present == 0 {
        return Err(io::Error::other("private-dir SDDL has no DACL"));
    }

    // Protected, so a later ACL change on %LOCALAPPDATA% cannot widen the directory.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            directory_acl,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }

    let mut label_acl: *mut ACL = ptr::null_mut();
    let mut label_present = 0;
    // SAFETY: same descriptor, still alive; the out pointers are ours.
    if unsafe {
        GetSecurityDescriptorSacl(
            descriptor.as_ptr(),
            &raw mut label_present,
            &raw mut label_acl,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if label_present == 0 {
        return Ok(());
    }

    // LABEL gets its own call: the mandatory label lives in the SACL, and writing it needs no
    // SeSecurityPrivilege the way an audit ACE would.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            label_acl,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    Ok(())
}

fn set_not_content_indexed(path: &Path) -> io::Result<()> {
    let wide = wide_path(path);
    // SAFETY: `wide` is NUL-terminated and lives for the call.
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(io::Error::last_os_error());
    }
    if attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0 {
        return Ok(());
    }
    // SAFETY: the same live path. Passing the current flags keeps them, and Windows ignores the
    // directory bit in a SetFileAttributesW call.
    if unsafe {
        SetFileAttributesW(
            wide.as_ptr(),
            attributes | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether this user may create and rename entries in `dir`. Opening the directory with the rights
/// a create needs lets the ACL answer, the way `access(W_OK | X_OK)` does on Unix.
pub(super) fn is_writable_dir(dir: &Path) -> bool {
    let wide = wide_path(dir);
    // SAFETY: `wide` is NUL-terminated and lives for the call; share-all keeps a concurrent scan or
    // rename from failing the check.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return false;
    }
    // SAFETY: `CreateFileW` returned a handle this process owns; `OwnedHandle` closes it.
    drop(unsafe { OwnedHandle::from_raw_handle(handle) });
    true
}

pub(super) fn is_on_read_only_volume(path: &Path) -> io::Result<bool> {
    let wide = wide_path(path);
    // SAFETY: `wide` is NUL-terminated and lives for the call; `FILE_FLAG_BACKUP_SEMANTICS` opens a
    // directory as well as a file.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` returned a handle this process owns; `OwnedHandle` closes it.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut flags = 0;
    // SAFETY: the handle is live for the call, and the null name buffers are allowed with size 0.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle.as_raw_handle().cast(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut flags,
            ptr::null_mut(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & FILE_READ_ONLY_VOLUME != 0)
}

/// Antivirus opens the fresh temp file as soon as it appears and may hold it without
/// `FILE_SHARE_DELETE`. Windows' rename is already atomic with POSIX semantics, so a short retry is
/// all the atomic-write contract needs.
pub(super) fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    const BACKOFF_MS: [u64; 5] = [20, 40, 80, 160, 320];
    let mut attempt = 0;
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(error) if attempt < BACKOFF_MS.len() && is_retryable(&error) => {
                std::thread::sleep(std::time::Duration::from_millis(BACKOFF_MS[attempt]));
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_retryable(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .is_some_and(|code| code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION)
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn win32_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX))
}

pub(super) fn verify_private_dir(path: &Path) -> Result<Repair, Refusal> {
    verify(path, true)
}

pub(super) fn verify_private_files<P: AsRef<Path>>(paths: &[P]) -> Result<Repair, Refusal> {
    let mut repair = Repair::None;
    for path in paths {
        match verify(path.as_ref(), false) {
            Ok(next) => repair = repair.merge(next),
            Err(Refusal::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
            Err(refusal) => return Err(refusal),
        }
    }
    Ok(repair)
}

fn verify(path: &Path, is_dir: bool) -> Result<Repair, Refusal> {
    let (handle, writable) = open_for_check(path, is_dir)?;
    let attributes = attribute_info(&handle).map_err(|error| io_refusal(path, error))?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Refusal::ReparsePoint {
            path: path.to_path_buf(),
        });
    }

    let sid = current_user_sid().map_err(|error| io_refusal(path, error))?;
    let user = UserSid::parse(&sid).map_err(|error| io_refusal(path, error))?;
    let security = SecurityInfo::read(&handle).map_err(|error| io_refusal(path, error))?;
    check_owner(path, &security, &user)?;
    let dacl_matches = check_dacl(path, &security, &user, is_dir)?;
    let label_matches = label_matches(&security).map_err(|error| io_refusal(path, error))?;
    let attribute_matches = attributes.FileAttributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0;

    if dacl_matches && label_matches && attribute_matches {
        return Ok(Repair::None);
    }
    let changes = Repair::Rewritten {
        dacl: !dacl_matches,
        label: !label_matches,
        attribute: !attribute_matches,
    };
    if !writable {
        return Err(io_refusal(path, repair_denied()));
    }
    repair(path, &handle, &sid, changes, attributes.FileAttributes)?;
    Ok(changes)
}

fn open_for_check(path: &Path, is_dir: bool) -> Result<(OwnedHandle, bool), Refusal> {
    match open(path, is_dir, true) {
        Ok(handle) => Ok((handle, true)),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => open(path, is_dir, false)
            .map(|handle| (handle, false))
            .map_err(|error| io_refusal(path, error)),
        Err(error) => Err(io_refusal(path, error)),
    }
}

fn open(path: &Path, is_dir: bool, write: bool) -> io::Result<OwnedHandle> {
    let mut access = FILE_READ_ATTRIBUTES | READ_CONTROL;
    if write {
        access |= WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES;
    }
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if is_dir {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let wide = wide_path(path);
    // SAFETY: `wide` is NUL-terminated and lives for the call; share-all lets an antivirus scan or
    // a rename race the check without failing it.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` returned a handle this process owns; `OwnedHandle` closes it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn attribute_info(handle: &OwnedHandle) -> io::Result<FILE_ATTRIBUTE_TAG_INFO> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: the handle is live and `info` outlives the call with the size the class expects.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle().cast(),
            FileAttributeTagInfo,
            (&raw mut info).cast::<c_void>(),
            ATTRIBUTE_TAG_INFO_LEN,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// An owned descriptor returned by `GetSecurityInfo`; the owner, DACL and SACL pointers point into
/// it and stay valid until it is freed.
struct SecurityInfo {
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
    sacl: *mut ACL,
    control: u16,
}

impl SecurityInfo {
    fn read(handle: &OwnedHandle) -> io::Result<Self> {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut sacl = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the handle is live; every out pointer is ours, and `GetSecurityInfo` allocates
        // the descriptor with `LocalAlloc`, which `SecurityInfo::drop` frees.
        let status = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                &raw mut owner,
                ptr::null_mut(),
                &raw mut dacl,
                &raw mut sacl,
                &raw mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }

        let mut info = Self {
            descriptor,
            owner,
            dacl,
            sacl,
            control: 0,
        };
        let descriptor = info.descriptor;
        let mut revision = 0;
        // SAFETY: `descriptor` is the live allocation above; the out pointers are ours.
        let control = unsafe {
            GetSecurityDescriptorControl(descriptor, &raw mut info.control, &raw mut revision)
        };
        if control == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }
}

impl Drop for SecurityInfo {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: `GetSecurityInfo` allocated the descriptor with `LocalAlloc`.
            unsafe {
                LocalFree(self.descriptor);
            }
        }
    }
}

/// The user's SID as a `LocalAlloc`'d binary SID. Comparisons go through `EqualSid`: SDDL text
/// prints well-known accounts as aliases (the built-in Administrator is `LA`), so a text match
/// against `S-1-5-…` would call the user's own ACE foreign.
struct UserSid(PSID);

impl UserSid {
    fn parse(text: &str) -> io::Result<Self> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid: PSID = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and lives for the call; `sid` is our out pointer.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sid))
    }
}

impl Drop for UserSid {
    fn drop(&mut self) {
        // SAFETY: `ConvertStringSidToSidW` allocated the SID with `LocalAlloc`.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn same_sid(left: PSID, right: PSID) -> bool {
    // SAFETY: both pointers reference valid SIDs that outlive the call.
    unsafe { EqualSid(left, right) != 0 }
}

fn is_well_known(sid: PSID, kind: WELL_KNOWN_SID_TYPE) -> bool {
    // SAFETY: `sid` references a valid SID that outlives the call.
    unsafe { IsWellKnownSid(sid, kind) != 0 }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Principal {
    User,
    System,
    Administrators,
}

fn principal(sid: PSID, user: &UserSid) -> Option<Principal> {
    if same_sid(sid, user.0) {
        Some(Principal::User)
    } else if is_well_known(sid, WinLocalSystemSid) {
        Some(Principal::System)
    } else if is_well_known(sid, WinBuiltinAdministratorsSid) {
        Some(Principal::Administrators)
    } else {
        None
    }
}

fn check_owner(path: &Path, security: &SecurityInfo, user: &UserSid) -> Result<(), Refusal> {
    if security.owner.is_null() {
        return Err(io_refusal(
            path,
            io::Error::new(io::ErrorKind::InvalidData, "path has no owner"),
        ));
    }
    if same_sid(security.owner, user.0)
        || is_well_known(security.owner, WinBuiltinAdministratorsSid)
    {
        return Ok(());
    }
    let owner = sid_to_string(security.owner).map_err(|error| io_refusal(path, error))?;
    Err(Refusal::Owner {
        path: path.to_path_buf(),
        owner,
    })
}

/// Returns whether the DACL is exactly what `private_dir` writes. Files inherit it from the
/// directory, so their DACL is not required to be marked protected; a directory's must be.
fn check_dacl(
    path: &Path,
    security: &SecurityInfo,
    user: &UserSid,
    is_dir: bool,
) -> Result<bool, Refusal> {
    if security.dacl.is_null() {
        return Ok(false);
    }
    let aces = dacl_aces(security.dacl).map_err(|error| io_refusal(path, error))?;
    let mut full = [false; 3];
    for ace in &aces {
        if ace.sid.is_null() {
            continue;
        }
        if let Some(who) = principal(ace.sid, user) {
            if ace.allowed && ace.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
                full[who as usize] = true;
            }
        } else if ace.allowed {
            let sid = sid_to_string(ace.sid).map_err(|error| io_refusal(path, error))?;
            return Err(Refusal::ForeignAce {
                path: path.to_path_buf(),
                sid,
            });
        }
    }
    let protected = !is_dir || security.control & SE_DACL_PROTECTED != 0;
    Ok(aces.len() == full.len()
        && aces.iter().all(|ace| ace.allowed && !ace.sid.is_null())
        && full.iter().all(|granted| *granted)
        && protected)
}

fn label_matches(security: &SecurityInfo) -> io::Result<bool> {
    if security.sacl.is_null() {
        return Ok(false);
    }
    let mut labels = 0;
    let mut matches = false;
    for ace in aces(security.sacl)? {
        // SAFETY: `GetAce` returned a pointer inside the live SACL, whose header is readable.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }
        labels += 1;
        // SAFETY: the ACE type above guarantees the mandatory-label layout.
        let label = unsafe { &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>() };
        let sid = sid_to_string((&raw const label.SidStart).cast_mut().cast::<c_void>())?;
        let required = SYSTEM_MANDATORY_LABEL_NO_READ_UP
            | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP;
        matches = sid == MEDIUM_INTEGRITY_SID && label.Mask & required == required;
    }
    Ok(labels == 1 && matches)
}

/// `sid` points into the ACL it was read from and is null for non-allow ACEs.
struct Ace {
    allowed: bool,
    mask: u32,
    sid: PSID,
}

fn dacl_aces(dacl: *const ACL) -> io::Result<Vec<Ace>> {
    let mut result = Vec::new();
    for ace in aces(dacl)? {
        // SAFETY: `GetAce` returned a pointer inside the live ACL, whose header is readable.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let (mask, sid_start) = match u32::from(header.AceType) {
            // SAFETY: the ACE type above guarantees the basic allowed layout.
            ACCESS_ALLOWED_ACE_TYPE => unsafe {
                let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                (ace.Mask, &raw const ace.SidStart)
            },
            // SAFETY: the ACE type above guarantees the object allowed layout.
            ACCESS_ALLOWED_OBJECT_ACE_TYPE => unsafe {
                let ace = &*ace.cast::<ACCESS_ALLOWED_OBJECT_ACE>();
                (ace.Mask, &raw const ace.SidStart)
            },
            _ => {
                result.push(Ace {
                    allowed: false,
                    mask: 0,
                    sid: ptr::null_mut(),
                });
                continue;
            }
        };
        result.push(Ace {
            allowed: true,
            mask,
            sid: sid_start.cast_mut().cast::<c_void>(),
        });
    }
    Ok(result)
}

fn aces(acl: *const ACL) -> io::Result<Vec<*mut c_void>> {
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `acl` points into a live descriptor and `size` outlives the call.
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut size).cast::<c_void>(),
            ACL_SIZE_LEN,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let capacity = usize::try_from(size.AceCount).expect("ACE count fits in usize on 64-bit");
    let mut result = Vec::with_capacity(capacity);
    for index in 0..size.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: `acl` is live and `ace` is an out pointer we own.
        if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        result.push(ace);
    }
    Ok(result)
}

fn repair(
    path: &Path,
    handle: &OwnedHandle,
    sid: &str,
    repair: Repair,
    attributes: u32,
) -> Result<(), Refusal> {
    let Repair::Rewritten {
        dacl,
        label,
        attribute,
    } = repair
    else {
        return Ok(());
    };
    let sddl = sddl::private_dir(sid).map_err(|error| io_refusal(path, error))?;
    let expected = SecurityDescriptor::from_sddl(&sddl).map_err(|error| io_refusal(path, error))?;

    if dacl {
        let acl = expected_dacl(&expected).map_err(|error| io_refusal(path, error))?;
        // SAFETY: the handle is live, `acl` points into `expected` (alive for the call), and
        // PROTECTED_DACL keeps a parent's ACL from widening the object later.
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io_refusal(path, win32_error(status)));
        }
    }

    if label {
        let sacl = expected_sacl(&expected).map_err(|error| io_refusal(path, error))?;
        // SAFETY: as above; the mandatory label lives in the SACL and needs no SeSecurityPrivilege.
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                sacl,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io_refusal(path, win32_error(status)));
        }
    }

    if attribute {
        let info = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: attributes | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        };
        // SAFETY: the handle is live and `info` outlives the call with the expected size.
        if unsafe {
            SetFileInformationByHandle(
                handle.as_raw_handle().cast(),
                FileBasicInfo,
                (&raw const info).cast::<c_void>(),
                BASIC_INFO_LEN,
            )
        } == 0
        {
            return Err(io_refusal(path, io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn expected_dacl(descriptor: &SecurityDescriptor) -> io::Result<*mut ACL> {
    let mut present = 0;
    let mut acl: *mut ACL = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: the descriptor is live; the out pointers are ours.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || acl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private-dir SDDL produced no DACL",
        ));
    }
    Ok(acl)
}

fn expected_sacl(descriptor: &SecurityDescriptor) -> io::Result<*mut ACL> {
    let mut present = 0;
    let mut acl: *mut ACL = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: the descriptor is live; the out pointers are ours.
    if unsafe {
        GetSecurityDescriptorSacl(
            descriptor.as_ptr(),
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || acl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private-dir SDDL produced no SACL",
        ));
    }
    Ok(acl)
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    if sid.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "null SID"));
    }
    let mut text = ptr::null_mut();
    // SAFETY: `sid` points into a live descriptor; `text` is an out pointer the call fills with a
    // NUL-terminated, `LocalAlloc`'d string.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `text` is a NUL-terminated UTF-16 string.
    let result = unsafe { wide_to_string(text) };
    // SAFETY: `LocalFree` matches the allocation `ConvertSidToStringSidW` made.
    unsafe {
        LocalFree(text.cast::<c_void>());
    }
    Ok(result)
}

/// SAFETY: `text` must point to a NUL-terminated UTF-16 string.
unsafe fn wide_to_string(text: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so this loop stays inside its allocation.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `text..text+len` is a valid, in-bounds slice of the allocation.
    let slice = unsafe { std::slice::from_raw_parts(text, len) };
    String::from_utf16_lossy(slice)
}

fn io_refusal(path: &Path, error: io::Error) -> Refusal {
    Refusal::Io {
        path: path.to_path_buf(),
        source: error,
    }
}

fn repair_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "not allowed to repair the permissions",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// Reads the DACL back and checks it structurally: SDDL text would show the built-in
    /// Administrator as an alias, which a SID string cannot match.
    fn assert_private_dacl(path: &Path) {
        let handle = open(path, true, false).expect("open");
        let security = SecurityInfo::read(&handle).expect("security");
        assert_ne!(
            security.control & SE_DACL_PROTECTED,
            0,
            "DACL not protected"
        );
        assert!(!security.dacl.is_null(), "no DACL");

        let user = UserSid::parse(&current_user_sid().expect("SID")).expect("user SID");
        let aces = dacl_aces(security.dacl).expect("aces");
        assert_eq!(aces.len(), 3);
        for who in [
            Principal::User,
            Principal::System,
            Principal::Administrators,
        ] {
            assert!(
                aces.iter().any(|ace| {
                    ace.allowed
                        && ace.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
                        && principal(ace.sid, &user) == Some(who)
                }),
                "missing full-control ACE for one principal"
            );
        }
    }

    #[test]
    fn private_dir_is_protected_owned_and_not_indexed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        ensure_private_dir(&nested).expect("create");
        ensure_private_dir(&nested).expect("tighten");

        let wide = wide_path(&nested);
        // SAFETY: `wide` is NUL-terminated.
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        assert_ne!(attributes, INVALID_FILE_ATTRIBUTES);
        assert_ne!(attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, 0);

        assert_private_dacl(&nested);
    }

    fn set_dacl(path: &Path, sddl: &str) {
        let descriptor = SecurityDescriptor::from_sddl(sddl).expect("descriptor");
        let mut present = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: the descriptor is live; the out pointers are ours.
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &raw mut present,
                    &raw mut dacl,
                    &raw mut defaulted,
                )
            },
            0
        );
        assert_ne!(present, 0);

        let wide = wide_path(path);
        // SAFETY: `wide` is NUL-terminated, `dacl` points into `descriptor`, and both outlive the
        // call.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
    }

    #[test]
    fn a_private_directory_passes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        ensure_private_dir(&nested).expect("create");
        assert_eq!(verify_private_dir(&nested).expect("verify"), Repair::None);
    }

    #[test]
    fn a_foreign_ace_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sid = current_user_sid().expect("SID");
        set_dacl(
            dir.path(),
            &format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;S-1-5-32-545)"),
        );
        match verify_private_dir(dir.path()) {
            Err(Refusal::ForeignAce { sid, .. }) => assert_eq!(sid, "S-1-5-32-545"),
            other => panic!("expected a foreign-ACE refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_narrow_dacl_is_repaired_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("data");
        fs::create_dir(&nested).expect("create");
        let sid = current_user_sid().expect("SID");
        set_dacl(&nested, &format!("D:P(A;OICI;FA;;;{sid})"));

        let repair = verify_private_dir(&nested).expect("verify");
        assert!(
            matches!(repair, Repair::Rewritten { dacl: true, .. }),
            "{repair:?}"
        );
        assert_eq!(
            verify_private_dir(&nested).expect("second verify"),
            Repair::None
        );
    }

    #[test]
    fn writable_and_read_only_checks() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(is_writable_dir(dir.path()));
        assert!(!is_writable_dir(&dir.path().join("missing")));
        assert!(!is_on_read_only_volume(dir.path()).expect("volume info"));
    }

    #[test]
    fn missing_files_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("absent");
        assert_eq!(
            verify_private_files(&[missing]).expect("verify"),
            Repair::None
        );
    }

    #[test]
    fn a_private_file_stays_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        ensure_private_dir(dir.path()).expect("create");
        let file = dir.path().join("refresh_token.enc");
        fs::write(&file, b"sealed").expect("write");

        let files = [file];
        verify_private_files(&files).expect("first check");
        assert_eq!(
            verify_private_files(&files).expect("second check"),
            Repair::None
        );
    }
}
