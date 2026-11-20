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

/// Convert a Rust `&str` into a NUL-terminated UTF-16 buffer for the Windows "W" functions.
/// (Same helper as in `win.rs`; both copies are private to their module.)
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}


pub fn is_elevated() -> bool {
    unsafe {
        // Will receive the handle of this process's token.
        let mut token: HANDLE = std::ptr::null_mut();
        // Open the token of the current process with permission to query it.
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        // Output structure; `TokenIsElevated` becomes non-zero when elevated.
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        // Windows stores here how many bytes it wrote (required, otherwise unused).
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            // The token to query.
            token,
            // Which piece of information we want: the elevation state.
            TokenElevation,
            // Pointer to our output structure (cast to the untyped pointer the API expects).
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            // Size of the output structure in bytes.
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            // Receives the number of bytes returned.
            &mut returned,
        );
        // The token handle is no longer needed.
        CloseHandle(token);
        // Elevated only if the query succeeded AND the flag is set.
        ok != 0 && elevation.TokenIsElevated != 0
    }
}


/// Returns as soon as the new process has been started (it does not wait for it). The new
/// process opens its own console window; that is why the program supports `--pause`, which
/// keeps that window open until Enter is pressed so the output can be read.
pub fn relaunch_elevated(args: &[String]) -> Result<(), String> {
    // Full path of the currently running exe, so the same program is started again.
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own path: {e}"))?;
    // Build one command-line string: every argument in double quotes (so paths with spaces
    // survive), separated by spaces.
    let params = args.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(" ");
    // Convert everything to UTF-16; these buffers must stay alive during the call below.
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
    // ShellExecuteW returns a value greater than 32 on success; 32 or less is an error code
    // (for example 5 when the user declines the UAC prompt).
    let code = result as isize;
    if code <= 32 {
        return Err(format!("could not start with Administrator rights (cancelled at the prompt? code {code})"));
    }
    Ok(())
}


/// Windows sometimes returns paths with the `\\?\` long-path prefix; Explorer's command line
/// handling does not like it, so it is removed.
fn exe_path() -> Result<String, String> {
    let p = std::env::current_exe().map_err(|e| format!("cannot find own path: {e}"))?;
    let s = p.to_string_lossy().to_string();
    Ok(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
}


fn write_default(subkey: &str, value: &str) -> Result<(), String> {
    let sub = to_wide(subkey);
    // Receives the handle of the created/opened key.
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
    // Registry functions return 0 (ERROR_SUCCESS) on success, otherwise the error code.
    if rc != 0 {
        return Err(format!("cannot create registry key '{subkey}' (error {rc})"));
    }
    let data = to_wide(value);
    let rc = unsafe {
        // Value name = null means the key's (Default) value. Type REG_SZ = string. The size is
        // in BYTES, including the terminating zero: each UTF-16 unit is 2 bytes.
        RegSetValueExW(key, std::ptr::null(), 0, REG_SZ, data.as_ptr().cast(), (data.len() * 2) as u32)
    };
    // Always close the key handle, even if setting the value failed.
    unsafe { RegCloseKey(key) };
    if rc != 0 {
        return Err(format!("cannot write registry value in '{subkey}' (error {rc})"));
    }
    Ok(())
}


pub fn install(force: bool) -> Result<String, String> {
    let exe = exe_path()?;
    let command = format!("\"{exe}\" --erase --pause{} \"%1\"", if force { " --force" } else { "" });
    // The menu text, as the (Default) value of the verb key...
    write_default(MENU_KEY, "Secure Erase with E-Shredder")?;
    // ...and the command line, as the (Default) value of its `command` subkey.
    write_default(&format!(r"{MENU_KEY}\command"), &command)?;
    Ok(command)
}

/// Remove the menu entry. Returns false if it was not installed.
/// `RegDeleteTreeW` deletes the key and everything below it (the `command` subkey).
pub fn uninstall() -> Result<bool, String> {
    let sub = to_wide(MENU_KEY);
    let rc = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, sub.as_ptr()) };
    match rc {
        0 => Ok(true),
        2 => Ok(false), // ERROR_FILE_NOT_FOUND
        e => Err(format!("cannot remove the registry key (error {e})")),
    }
}
