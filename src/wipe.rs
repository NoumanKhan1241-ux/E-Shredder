use std::io::Read;

use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

use crate::mft::Run;
use crate::win::Volume;

/// `Clone, Copy` make it as cheap to pass around as a number; `Debug` lets the program print
#[derive(Clone, Copy, Debug)]
pub enum Pattern {
    /// Every byte `0x00`.
    Zeros,
    /// Every byte `0xFF` (all bits set).
    Ones,
    /// Cryptographically random bytes from the operating system.
    Random,
}


/// Order matters: random data first hides the original pattern, all-ones flips every bit, and
/// the final all-zero pass leaves the clusters in a known state that `verify_zeroed` can check.
pub const PASSES: [Pattern; 3] = [Pattern::Random, Pattern::Ones, Pattern::Zeros];


const CHUNK: usize = 1 << 20;

/// Fill `buf` completely with the bytes of pattern `p`.

/// For `Zeros` and `Ones` this is a simple `fill`. For `Random` the Windows system RNG is
/// asked for `buf.len()` random bytes. Returns an error only if the RNG call fails.
fn fill(buf: &mut [u8], p: Pattern) -> Result<(), String> {
    match p {
        Pattern::Zeros => buf.fill(0),
        Pattern::Ones => buf.fill(0xFF),
        Pattern::Random => {
            let status = unsafe {
                BCryptGenRandom(
                    // No algorithm handle: together with the flag below this means
                    // "use the system's default random number generator".
                    std::ptr::null_mut(),
                    // Where to put the random bytes, and how many.
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    // Flag: use the system-preferred RNG.
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            // BCryptGenRandom returns an NTSTATUS; 0 means success.
            if status != 0 {
                return Err(format!("BCryptGenRandom failed (NTSTATUS 0x{status:X})"));
            }
        }
    }
    Ok(())
}


/// If even one byte differs, an error is returned and the caller stops before anything is
/// written.
pub fn verify_runs(
    vol: &Volume,
    spec: &str, // file path, or "path:streamname" for an alternate data stream
    runs: &[Run],
    cluster_size: u64,
    real_size: u64,
) -> Result<(), String> {
    // Open the file the ordinary way. Windows resolves the real data through NTFS itself, so
    // this is the "ground truth" we compare the raw clusters against.
    let mut f = std::fs::File::open(spec).map_err(|e| format!("cannot open '{spec}' to verify: {e}"))?;
    // `raw` holds bytes read directly from the clusters; `via_fs` holds bytes read through the
    // file system. Both are one chunk long.
    let mut raw = vec![0u8; CHUNK];
    let mut via_fs = vec![0u8; CHUNK];
    // How many file bytes are still left to compare. It counts down to zero; the file ends
    // before the end of its last cluster, so we stop exactly at `real_size`.
    let mut remaining = real_size;

    // Walk the runs in order: that is the order of the file's content (VCN 0, 1, 2, ...).
    for (i, r) in runs.iter().enumerate() {
        // A sparse run has no clusters on disk, so a raw comparison is impossible.
        if r.sparse {
            return Err(format!("run {i} is sparse; not supported"));
        }
        // Total size of this run in bytes.
        let run_bytes = r.clusters * cluster_size;
        // How far into this run we have processed (in bytes).
        let mut off = 0u64;
        while off < run_bytes && remaining > 0 {
            // Size of this piece: a full chunk, or whatever is left of the run.
            let n = (CHUNK as u64).min(run_bytes - off) as usize;
            // Raw read from the volume: byte position = start cluster * cluster size + offset
            // inside the run. `n` is a multiple of the cluster size, so it is sector-aligned.
            vol.read_at(r.lcn * cluster_size + off, &mut raw[..n])?;
            // Compare only real file bytes, never the slack at the end of the last cluster.
            let want = (n as u64).min(remaining) as usize;
            // Read the same number of bytes sequentially through the normal file API.
            f.read_exact(&mut via_fs[..want])
                .map_err(|e| format!("cannot read '{spec}': {e}"))?;
            // The two views must be identical; otherwise our idea of where the file lives is
            // wrong and writing would destroy other data.
            if raw[..want] != via_fs[..want] {
                return Err(format!(
                    "MISMATCH: run {i} (LCN 0x{:X}) at +{off} differs from the file contents",
                    r.lcn
                ));
            }
            // Advance inside the run and reduce the number of bytes still to check.
            off += n as u64;
            remaining -= want as u64;
        }
    }
    // If bytes are left over, the runs describe less data than the file size says.
    if remaining != 0 {
        return Err(format!("runs cover {} bytes less than the file size", remaining));
    }
    Ok(())
}

/// Whole clusters are overwritten, including the unused slack at the end of the last one,
/// because the slack may still contain old file data. After each pass the volume is flushed so
/// the pass has really reached the disk before the next one starts.
pub fn wipe_runs(vol: &Volume, runs: &[Run], cluster_size: u64, passes: &[Pattern]) -> Result<u64, String> {
    // One reusable buffer; it is refilled with the pattern before every write.
    let mut buf = vec![0u8; CHUNK];
    // Total bytes written in one pass (reported to the caller).
    let mut per_pass = 0u64;
    // `pi` = pass index (for the progress message), `pat` = the pattern of this pass.
    for (pi, &pat) in passes.iter().enumerate() {
        println!("    pass {}/{}: {:?}", pi + 1, passes.len(), pat);
        // Reset the counter so it holds the size of ONE pass, not the sum of all passes.
        per_pass = 0;
        // Skip sparse runs: there are no clusters behind them, writing there would hit
        // unrelated clusters (their `lcn` is meaningless).
        for r in runs.iter().filter(|r| !r.sparse) {
            let run_bytes = r.clusters * cluster_size;
            // Offset inside the run, in bytes.
            let mut off = 0u64;
            while off < run_bytes {
                // Chunk of at most 1 MiB, or the remainder of the run.
                let n = (CHUNK as u64).min(run_bytes - off) as usize;
                // Prepare the pattern in the buffer (fresh random bytes for every chunk).
                fill(&mut buf[..n], pat)?;
                // Write it to the exact position of these clusters on the volume.
                vol.write_at(r.lcn * cluster_size + off, &buf[..n])?;
                off += n as u64;
            }
            per_pass += run_bytes;
        }
        // Push cached writes to the physical disk before the next pass overwrites them.
        vol.flush()?;
    }
    Ok(per_pass)
}

/// Read the clusters back and make sure they are all zero.
///
/// Called right after `wipe_runs`. Because the last pass in `PASSES` is zeros, every byte of
/// every non-sparse run must now be 0. This proves the writes really reached the disk, not
/// only the memory cache.
pub fn verify_zeroed(vol: &Volume, runs: &[Run], cluster_size: u64) -> Result<(), String> {
    // One reusable buffer for the data read back.
    let mut buf = vec![0u8; CHUNK];
    // Same iteration scheme as `wipe_runs`: every non-sparse run, chunk by chunk.
    for r in runs.iter().filter(|r| !r.sparse) {
        let run_bytes = r.clusters * cluster_size;
        let mut off = 0u64;
        while off < run_bytes {
            let n = (CHUNK as u64).min(run_bytes - off) as usize;
            // Read the chunk from the raw volume.
            vol.read_at(r.lcn * cluster_size + off, &mut buf[..n])?;
            // Any non-zero byte means the wipe failed at this place.
            if buf[..n].iter().any(|&b| b != 0) {
                return Err(format!("non-zero data found at LCN 0x{:X} +{off} after wiping", r.lcn));
            }
            off += n as u64;
        }
    }
    Ok(())
}
