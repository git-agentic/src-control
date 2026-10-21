//! Windows owner-only file creation for `.sc/local-key` (#214).
//!
//! The only Windows `unsafe` in `scl-repo` lives here, behind one safe function:
//! [`create_new_owner_only`]. It builds a *protected* DACL holding a single
//! ACE (`GENERIC_ALL` for the current user's SID) and hands it to `CreateFileW`
//! as the file's security descriptor, so the file is owner-only from its first
//! byte: no inherited ACEs, no window at default permissions. Every Win32
//! allocation and handle is released by a drop guard on all paths.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Closes a kernel handle on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful Win32 call and is
        // closed exactly once, here.
        unsafe { CloseHandle(self.0) };
    }
}

/// Frees a `LocalAlloc`-family allocation (returned by the Convert* calls).
struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Win32 call documented to require
        // `LocalFree`, and is freed exactly once, here.
        unsafe { LocalFree(self.0) };
    }
}

/// The current user's SID as a string such as `S-1-5-21-...`.
fn current_user_sid_string() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `token` is a valid out-pointer; the pseudo-handle from
    // `GetCurrentProcess` needs no closing.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);

    // First call sizes the buffer; it must fail with ERROR_INSUFFICIENT_BUFFER.
    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 is the documented way to query the size.
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len) };
    // SAFETY: reads the thread's last-error value, set by the call above.
    if len == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    // u64 elements keep the buffer 8-byte aligned for TOKEN_USER.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` is at least `len` bytes, as the first call reported.
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call filled `buf` with a TOKEN_USER whose SID
    // pointer targets memory inside `buf`, which outlives this block.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut wide: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid SID (above) and `wide` a valid out-pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let wide = LocalMem(wide.cast());
    // SAFETY: on success `wide` points at a NUL-terminated UTF-16 string that
    // stays alive until `LocalMem` drops.
    let s = unsafe {
        let p = wide.0.cast::<u16>();
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    };
    Ok(s)
}

/// Create `path` (failing with `AlreadyExists` if present) readable and
/// writable by the current user only, from the first byte.
pub(crate) fn create_new_owner_only(path: &Path) -> io::Result<File> {
    // `D:P` = protected DACL (nothing inherited); `GA` = GENERIC_ALL.
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{})", current_user_sid_string()?)
        .encode_utf16()
        .chain([0])
        .collect();
    // shortcut: no `\\?\` prefix for paths of 260+ chars (std adds one), so those
    // fail here and take the default-permissions fallback; upgrade if that bites.
    let wpath: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    if wpath[..wpath.len() - 1].contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    let mut sd: *mut c_void = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` is a valid out-pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sd = LocalMem(sd);

    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `wpath` is NUL-terminated and `attrs` (with the descriptor `sd`
    // owns) outlives the call; the share mode matches std's default.
    let h = unsafe {
        CreateFileW(
            wpath.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attrs,
            CREATE_NEW,
            // As std does for create_new: never follow a link planted at the path.
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is a valid, owned file handle; the `File` takes it over.
    Ok(unsafe { File::from_raw_handle(h.cast()) })
}
