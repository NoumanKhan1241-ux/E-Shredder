use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};

use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, GetFileInformationByHandle, ReadFile, SetFilePointerEx,
    WriteFile, BY_HANDLE_FILE_INFORMATION, FILE_BEGIN, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
// Control codes that are sent to the volume: lock it (exclusive access) or dismount it.
use windows_sys::Win32::System::Ioctl::{FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME};
// `DeviceIoControl` is the generic "send a control code to a device or volume" function.
use windows_sys::Win32::System::IO::DeviceIoControl;


fn to_wide(s: &str) -> Vec<u16> {
    // `encode_wide()` produces the UTF-16 units; `chain(once(0))` appends the terminating
    // zero that marks the end of the string for the C side.
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Used by `get_file_reference` (to open the target file) and by `Volume::open` (to open the
/// raw volume). On failure the Win32 error code is returned inside the error string, which
/// makes problems such as error 5 (access denied, not running as Administrator) easy to spot.
fn open_path(path: &str, access: u32) -> Result<HANDLE, String> {
    // Convert once; `wide` must stay alive until CreateFileW returns.
    let wide = to_wide(path);
    // Every Win32 call is `unsafe` because we pass raw pointers.
    let h = unsafe {
        CreateFileW(
            // 1st argument: pointer to the NUL-terminated UTF-16 path.
            wide.as_ptr(),
            // 2nd argument: the access rights we ask for.
            access,
            // 3rd argument: sharing mode. We allow other programs to keep reading and writing
            // the same object while we have it open. For a mounted volume Windows refuses to
            // open it at all unless both share flags are given.
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            // 4th argument: security attributes. null = default security.
            std::ptr::null(),
            // 5th argument: creation disposition. OPEN_EXISTING means "fail if it does not
            // exist" - we must never create anything by accident.
            OPEN_EXISTING,
            // 6th argument: flags. BACKUP_SEMANTICS is required to open directories and is
            // harmless for files and volumes, so one function can open all three.
            FILE_FLAG_BACKUP_SEMANTICS,
            // 7th argument: template file handle. Not used, so null.
            std::ptr::null_mut(),
        )
    };
    // CreateFileW does not return null on failure but the special value INVALID_HANDLE_VALUE.
    if h == INVALID_HANDLE_VALUE {
        // GetLastError must be called right after the failing call, before any other Win32
        // call can overwrite the error code.
        Err(format!("cannot open '{path}' (Win32 error {})", unsafe { GetLastError() }))
    } else {
        Ok(h)
    }
}

/// The sequence number is increased every time an MFT record is reused for a different file,
/// so it lets `main.rs` detect stale references (a safety check).
pub fn get_file_reference(path: &str) -> Result<u64, String> {
    let h = open_path(path, GENERIC_READ)?;
    // `BY_HANDLE_FILE_INFORMATION` is a plain C struct that Windows fills in. `zeroed()` gives
    // us an all-zero instance, which is a valid starting state for this struct.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // Ask Windows to fill `info` (attributes, sizes, timestamps and the 64-bit file index).
    let ok = unsafe { GetFileInformationByHandle(h, &mut info) };
    // Save the error code BEFORE CloseHandle, because CloseHandle may overwrite it.
    let err = unsafe { GetLastError() };
    // We no longer need the handle; always release it, success or not.
    unsafe { CloseHandle(h) };
    // GetFileInformationByHandle returns 0 on failure.
    if ok == 0 {
        return Err(format!("cannot get file ID (Win32 error {err})"));
    }
    // The 64-bit ID is delivered as two 32-bit halves; glue them back together.
    Ok(((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64)
}


pub struct Volume {
    /// The underlying Windows handle. Private: nobody outside this module can misuse it.
    handle: HANDLE,
}

impl Volume {

    pub fn open(drive: char, write: bool) -> Result<Self, String> {
        // Choose the access rights depending on whether we intend to write.
        let access = if write { GENERIC_READ | GENERIC_WRITE } else { GENERIC_READ };
        Ok(Volume { handle: open_path(&format!(r"\\.\{}:", drive), access)? })
    }

   
    fn seek(&self, offset: u64) -> Result<(), String> {
        let ok = unsafe {
            // Arguments: handle, distance (signed 64-bit), where to store the new position
            // (null = we do not need it), and the origin FILE_BEGIN = start of the volume.
            SetFilePointerEx(self.handle, offset as i64, std::ptr::null_mut(), FILE_BEGIN)
        };
        if ok == 0 {
            return Err(format!("seek to {offset} failed (Win32 error {})", unsafe { GetLastError() }));
        }
        Ok(())
    }

    
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        self.seek(offset)?;
        let mut read: u32 = 0;
        let ok = unsafe {
           
            ReadFile(self.handle, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(format!("read at {offset} failed (Win32 error {})", unsafe { GetLastError() }));
        }
        
        if read as usize != buf.len() {
            return Err(format!("short read at offset {offset}"));
        }
        Ok(())
    }

   
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), String> {
        self.seek(offset)?;
        // Windows reports how many bytes were written here.
        let mut written: u32 = 0;
        let ok = unsafe {
            WriteFile(self.handle, buf.as_ptr().cast(), buf.len() as u32, &mut written, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(format!("write at {offset} failed (Win32 error {})", unsafe { GetLastError() }));
        }
        // A short write would leave old data behind - fatal for a secure eraser.
        if written as usize != buf.len() {
            return Err(format!("short write at offset {offset}"));
        }
        Ok(())
    }

    /// Without this, "written" data may still sit in memory. It is called after each wipe pass
    /// and after the MFT record write so that each pass really reaches the disk.
    pub fn flush(&self) -> Result<(), String> {
        if unsafe { FlushFileBuffers(self.handle) } == 0 {
            return Err(format!("flush failed (Win32 error {})", unsafe { GetLastError() }));
        }
        Ok(())
    }

    
    /// The two operations we use take no input and return no output data, so all buffer
    /// arguments are null/zero.
    fn ioctl(&self, code: u32, what: &str) -> Result<(), String> {
        // DeviceIoControl requires a place to store "bytes returned", even if unused.
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                // The volume handle.
                self.handle,
                // The control code, e.g. FSCTL_LOCK_VOLUME.
                code,
                // Input buffer pointer and size: none.
                std::ptr::null(),
                0,
                // Output buffer pointer and size: none.
                std::ptr::null_mut(),
                0,
                // Receives the number of bytes returned (always 0 here).
                &mut returned,
                // OVERLAPPED = null: wait synchronously.
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("{what} failed (Win32 error {})", unsafe { GetLastError() }));
        }
        Ok(())
    }


    pub fn lock(&self) -> Result<(), String> {
        self.ioctl(FSCTL_LOCK_VOLUME, "locking the volume")
    }


    pub fn dismount(&self) -> Result<(), String> {
        self.ioctl(FSCTL_DISMOUNT_VOLUME, "dismounting the volume")
    }
}

/// Automatic cleanup: when a `Volume` goes out of scope (or is passed to `drop(...)`), its
/// handle is closed. Closing the handle also releases a lock taken with `Volume::lock`.
impl Drop for Volume {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}
