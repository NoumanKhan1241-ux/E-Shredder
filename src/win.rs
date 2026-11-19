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
use windows_sys::Win32::System::Ioctl::{FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME};
use windows_sys::Win32::System::IO::DeviceIoControl;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn open_path(path: &str, access: u32) -> Result<HANDLE, String> {
    let wide = to_wide(path);
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(format!("cannot open '{path}' (Win32 error {})", unsafe { GetLastError() }))
    } else {
        Ok(h)
    }
}

/// 64-bit NTFS file reference: low 48 bits = MFT record number, high 16 = sequence number.
pub fn get_file_reference(path: &str) -> Result<u64, String> {
    let h = open_path(path, GENERIC_READ)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(h, &mut info) };
    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return Err(format!("cannot get file ID (Win32 error {err})"));
    }
    Ok(((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64)
}

pub struct Volume {
    handle: HANDLE,
}

impl Volume {
    /// `write = true` opens the volume for read+write (needed for erasing).
    pub fn open(drive: char, write: bool) -> Result<Self, String> {
        let access = if write { GENERIC_READ | GENERIC_WRITE } else { GENERIC_READ };
        Ok(Volume { handle: open_path(&format!(r"\\.\{}:", drive), access)? })
    }

    fn seek(&self, offset: u64) -> Result<(), String> {
        let ok = unsafe {
            SetFilePointerEx(self.handle, offset as i64, std::ptr::null_mut(), FILE_BEGIN)
        };
        if ok == 0 {
            return Err(format!("seek to {offset} failed (Win32 error {})", unsafe { GetLastError() }));
        }
        Ok(())
    }

    /// Raw volume I/O must be sector-aligned: offset and length multiples of the sector size.
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
        let mut written: u32 = 0;
        let ok = unsafe {
            WriteFile(self.handle, buf.as_ptr().cast(), buf.len() as u32, &mut written, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(format!("write at {offset} failed (Win32 error {})", unsafe { GetLastError() }));
        }
        if written as usize != buf.len() {
            return Err(format!("short write at offset {offset}"));
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), String> {
        if unsafe { FlushFileBuffers(self.handle) } == 0 {
            return Err(format!("flush failed (Win32 error {})", unsafe { GetLastError() }));
        }
        Ok(())
    }

    fn ioctl(&self, code: u32, what: &str) -> Result<(), String> {
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                code,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("{what} failed (Win32 error {})", unsafe { GetLastError() }));
        }
        Ok(())
    }

    /// Fails if any file on the volume is open. The lock is released when the handle closes.
    pub fn lock(&self) -> Result<(), String> {
        self.ioctl(FSCTL_LOCK_VOLUME, "locking the volume")
    }

    /// Drops Windows' cached view of the volume; it remounts on next access.
    pub fn dismount(&self) -> Result<(), String> {
        self.ioctl(FSCTL_DISMOUNT_VOLUME, "dismounting the volume")
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}