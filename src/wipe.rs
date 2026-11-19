use std::io::Read;

use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

use crate::mft::Run;
use crate::win::Volume;

#[derive(Clone, Copy, Debug)]
pub enum Pattern {
    Zeros,
    Ones,
    Random,
}

/// The last pass is zeros so we can read everything back and prove it is gone.
pub const PASSES: [Pattern; 3] = [Pattern::Random, Pattern::Ones, Pattern::Zeros];

/// 1 MiB: a multiple of every sector and cluster size NTFS uses.
const CHUNK: usize = 1 << 20;

fn fill(buf: &mut [u8], p: Pattern) -> Result<(), String> {
    match p {
        Pattern::Zeros => buf.fill(0),
        Pattern::Ones => buf.fill(0xFF),
        Pattern::Random => {
            let status = unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(format!("BCryptGenRandom failed (NTSTATUS 0x{status:X})"));
            }
        }
    }
    Ok(())
}

/// Read the file through the normal Windows API and compare it with the raw clusters
/// named by `runs`. Proves the data runs really are this file's data.
pub fn verify_runs(
    vol: &Volume,
    spec: &str, // file path, or "path:streamname" for an alternate data stream
    runs: &[Run],
    cluster_size: u64,
    real_size: u64,
) -> Result<(), String> {
    let mut f = std::fs::File::open(spec).map_err(|e| format!("cannot open '{spec}' to verify: {e}"))?;
    let mut raw = vec![0u8; CHUNK];
    let mut via_fs = vec![0u8; CHUNK];
    let mut remaining = real_size;

    for (i, r) in runs.iter().enumerate() {
        if r.sparse {
            return Err(format!("run {i} is sparse; not supported"));
        }
        let run_bytes = r.clusters * cluster_size;
        let mut off = 0u64;
        while off < run_bytes && remaining > 0 {
            let n = (CHUNK as u64).min(run_bytes - off) as usize;
            vol.read_at(r.lcn * cluster_size + off, &mut raw[..n])?;
            let want = (n as u64).min(remaining) as usize;
            f.read_exact(&mut via_fs[..want])
                .map_err(|e| format!("cannot read '{spec}': {e}"))?;
            if raw[..want] != via_fs[..want] {
                return Err(format!(
                    "MISMATCH: run {i} (LCN 0x{:X}) at +{off} differs from the file contents",
                    r.lcn
                ));
            }
            off += n as u64;
            remaining -= want as u64;
        }
    }
    if remaining != 0 {
        return Err(format!("runs cover {} bytes less than the file size", remaining));
    }
    Ok(())
}

/// Overwrite every allocated cluster of `runs`, one pass per pattern. Returns bytes per pass.
pub fn wipe_runs(vol: &Volume, runs: &[Run], cluster_size: u64, passes: &[Pattern]) -> Result<u64, String> {
    let mut buf = vec![0u8; CHUNK];
    let mut per_pass = 0u64;
    for (pi, &pat) in passes.iter().enumerate() {
        println!("    pass {}/{}: {:?}", pi + 1, passes.len(), pat);
        per_pass = 0;
        for r in runs.iter().filter(|r| !r.sparse) {
            let run_bytes = r.clusters * cluster_size;
            let mut off = 0u64;
            while off < run_bytes {
                let n = (CHUNK as u64).min(run_bytes - off) as usize;
                fill(&mut buf[..n], pat)?;
                vol.write_at(r.lcn * cluster_size + off, &buf[..n])?;
                off += n as u64;
            }
            per_pass += run_bytes;
        }
        vol.flush()?;
    }
    Ok(per_pass)
}

/// Read the clusters back and make sure they are all zero.
pub fn verify_zeroed(vol: &Volume, runs: &[Run], cluster_size: u64) -> Result<(), String> {
    let mut buf = vec![0u8; CHUNK];
    for r in runs.iter().filter(|r| !r.sparse) {
        let run_bytes = r.clusters * cluster_size;
        let mut off = 0u64;
        while off < run_bytes {
            let n = (CHUNK as u64).min(run_bytes - off) as usize;
            vol.read_at(r.lcn * cluster_size + off, &mut buf[..n])?;
            if buf[..n].iter().any(|&b| b != 0) {
                return Err(format!("non-zero data found at LCN 0x{:X} +{off} after wiping", r.lcn));
            }
            off += n as u64;
        }
    }
    Ok(())
}