
use std::thread::sleep;
use std::time::Duration;

use crate::mft::*;
use crate::win::Volume;


/// The retries exist because the wipe stage dismounts the volume (see `Volume::dismount`).
/// Windows remounts it automatically on the next access, but the first attempt(s) may fail
/// while that happens.
fn delete_with_retry(path: &str) -> Result<(), String> {
    let mut last = String::new();
   
    for _ in 0..6 {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        sleep(Duration::from_millis(500));
    }
    Err(format!("could not delete '{path}': {last}"))
}


/// A lock can fail only briefly (for example while antivirus or the search indexer touches the
/// drive), so retrying avoids needless failures. Returns the last error if every attempt fails.
fn lock_with_retry(vol: &Volume, attempts: u32) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..attempts {
        match vol.lock() {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        sleep(Duration::from_millis(500));
    }
    Err(last)
}


/// Windows only allows raw writes through a volume handle once the volume is locked or
/// dismounted, so every writing stage starts with this call. With `force` the lock is tried
/// only twice (about one second) before falling back; without it ten times (about five
/// seconds) and then an explanatory error is returned.
pub fn acquire_volume(vol: &Volume, force: bool) -> Result<(), String> {
    match lock_with_retry(vol, if force { 2 } else { 10 }) {
        Ok(()) => Ok(()),
        // The lock failed but the caller allows the fallback: tell the user, then dismount.
        Err(e) if force => {
            println!("  lock failed ({e})");
            println!("  --force: dismounting the volume instead; open files on this drive lose their handles");
            vol.dismount()
        }
        // The lock failed and no fallback is allowed: explain the usual causes.
        Err(e) => Err(format!(
            "{e}. Something has this drive open (an Explorer window showing it, the disk editor, \
             a shell inside it). Close it and retry, or remove --strict to dismount the drive instead."
        )),
    }
}


/// Opens the volume for writing and tries `acquire_volume`. The handle is dropped at the end
/// of the function, which releases the lock again; the real work happens later. The point is
/// only to fail early, while the file still exists.
fn preflight(drive: char, force: bool) -> Result<(), String> {
    let vol = Volume::open(drive, true)?;
    acquire_volume(&vol, force) // dropping the handle releases the lock
}


/// If the scrub fails after the file was already deleted, the error message tells the user
/// that the data is wiped but the record is not, and shows the `--scrub-record` command that
/// repeats just the scrub.
pub fn delete_and_scrub(
    drive: char,
    path: &str,
    rec_off: u64,
    record_number: u64,
    record_size: usize,
    force: bool,
) -> Result<(), String> {
    println!("Finishing     :");
    // Stage 1: confirm we will be able to write before we delete.
    preflight(drive, force)?;
    // Stage 2: let NTFS delete the file consistently.
    delete_with_retry(path)?;
    println!("  file deleted through the file system (not moved to the Recycle Bin)");

    // Stage 3: scrub the leftovers. `map_err` wraps any error with an explanation of the exact
    // state we are in and how to finish the job.
    scrub_record(drive, rec_off, record_number, record_size, force).map_err(|e| {
        format!(
            "{e}\n  The file is deleted and its data wiped, but the freed MFT record was NOT scrubbed.\n  \
             Fix the problem, then run:  e-shredder --scrub-record {drive}: {record_number}"
        )
    })
}


/// Used by the command `e-shredder --scrub-record X: 50` to finish a job whose final stage
/// failed. Because the file no longer exists, the record's position is recomputed here from
/// the boot sector and the MFT's own run list.
pub fn scrub_by_number(drive: char, record_number: u64, force: bool) -> Result<(), String> {
    if record_number < 24 {
        return Err("refusing: records below 24 are NTFS system files".into());
    }
    
    let vol = Volume::open(drive, false)?;
    let mut boot = [0u8; 512];
    vol.read_at(0, &mut boot)?;
    let b = parse_boot_sector(&boot)?;
    let mft_runs = load_mft_runs(&vol, &b)?;
    let rec_off = mft_record_offset(&mft_runs, b.cluster_size as u64, b.record_size as u64, record_number)
        .ok_or("record number lies outside the MFT")?;
    drop(vol);
    scrub_record(drive, rec_off, record_number, b.record_size as usize, force)
}


fn scrub_record(
    drive: char,
    rec_off: u64,
    record_number: u64,
    record_size: usize,
    force: bool,
) -> Result<(), String> {
    let vol = Volume::open(drive, true)?;
    acquire_volume(&vol, force)?;
    vol.flush()?; 
    // Read the record (fixups already removed by `read_record`).
    let mut rec = read_record(&vol, rec_off, record_size)?;
    // Header offset 0x2C holds the record's own number; offset 0x16 holds the flags.
    let own_number = u32::from_le_bytes(rec[0x2C..0x30].try_into().unwrap()) as u64;
    let flags = u16::from_le_bytes([rec[0x16], rec[0x17]]);
    // Safety check 1: the record at this position must be the one we expect.
    if own_number != record_number {
        return Err(format!("record at 0x{rec_off:X} is #{own_number}, expected #{record_number}; nothing written"));
    }
    // Safety check 2: it must be marked FREE. If it is still in use, NTFS has not written the
    // delete yet, or has already given the record to a new file - in both cases do not touch it.
    if flags & 0x01 != 0 {
        return Err("the MFT record is marked in use (not yet written by NTFS, or reused); nothing written".into());
    }
    println!("  MFT record #{record_number} is marked free on disk (in-use flag cleared by NTFS)");

    // Informational only: show what NTFS left behind. Parsing may fail on an odd record; that
    // does not matter because the scrub below does not depend on it.
    if let Ok(p) = parse_record(&rec) {
        println!(
            "  freed record still holds: names {:?}, {} data stream(s) -> scrubbing",
            p.file_names,
            p.streams.len()
        );
    }

    scrub_free_record(&mut rec)?;
    protect_fixups(&mut rec)?;
    vol.write_at(rec_off, &rec)?;
    vol.flush()?;

    let check = read_record(&vol, rec_off, record_size)?;
    let p = parse_record(&check)?;
    if p.in_use || !p.file_names.is_empty() || !p.streams.is_empty() {
        return Err("verification failed: remnants still present in the record".into());
    }
    println!("  freed MFT record scrubbed and verified (no name, no data left)");

    
    let _ = vol.dismount(); // may already be dismounted by the --force fallback; ignore that
    Ok(())
}
