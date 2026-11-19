use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const MENU_KEY: &str = r"Software\Classes\*\shell\EShredder";

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

// ---------- elevation ----------
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Start this same program again with the "runas" verb (shows the UAC prompt).
pub fn relaunch_elevated(args: &[String]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own path: {e}"))?;
    let params = args.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(" ");
    let verb = to_wide("runas");
    let file = to_wide(&exe.to_string_lossy());
    let params_w = to_wide(&params);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params_w.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    let code = result as isize;
    if code <= 32 {
        return Err(format!("could not start with Administrator rights (cancelled at the prompt? code {code})"));
    }
    Ok(())
}

// ---------- context menu registration ----------
fn exe_path() -> Result<String, String> {
    let p = std::env::current_exe().map_err(|e| format!("cannot find own path: {e}"))?;
    let s = p.to_string_lossy().to_string();
    Ok(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
}

/// Create `subkey` under HKCU and set its (Default) value.
fn write_default(subkey: &str, value: &str) -> Result<(), String> {
    let sub = to_wide(subkey);
    let mut key: HKEY = std::ptr::null_mut();
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            sub.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(format!("cannot create registry key '{subkey}' (error {rc})"));
    }
    let data = to_wide(value);
    let rc = unsafe {
        RegSetValueExW(key, std::ptr::null(), 0, REG_SZ, data.as_ptr().cast(), (data.len() * 2) as u32)
    };
    unsafe { RegCloseKey(key) };
    if rc != 0 {
        return Err(format!("cannot write registry value in '{subkey}' (error {rc})"));
    }
    Ok(())
}

/// Register "Secure Erase with E-Shredder" for all files. Returns the command line stored.
pub fn install(force: bool) -> Result<String, String> {
    let exe = exe_path()?;
    let command = format!("\"{exe}\" --erase --pause{} \"%1\"", if force { " --force" } else { "" });
    write_default(MENU_KEY, "Secure Erase with E-Shredder")?;
    write_default(&format!(r"{MENU_KEY}\command"), &command)?;
    Ok(command)
}

/// Remove the menu entry. Returns false if it was not installed.
pub fn uninstall() -> Result<bool, String> {
    let sub = to_wide(MENU_KEY);
    let rc = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, sub.as_ptr()) };
    match rc {
        0 => Ok(true),
        2 => Ok(false), // ERROR_FILE_NOT_FOUND
        e => Err(format!("cannot remove the registry key (error {e})")),
    }
}