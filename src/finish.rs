use std::thread::sleep;
use std::time::Duration;

use crate::mft::*;
use crate::win::Volume;

fn delete_with_retry(path: &str) -> Result<(), String> {
    let mut last = String::new();
    // After the wipe stage dismounts the volume, Windows remounts it on first access.
    for _ in 0..6 {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        sleep(Duration::from_millis(500));
    }
    Err(format!("could not delete '{path}': {last}"))
}

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

/// Get exclusive control of the volume for raw writes: lock it. If that fails and `force`
/// is set, dismount it instead (programs with files open on it lose their handles).
pub fn acquire_volume(vol: &Volume, force: bool) -> Result<(), String> {
    match lock_with_retry(vol, if force { 2 } else { 10 }) {
        Ok(()) => Ok(()),
        Err(e) if force => {
            println!("  lock failed ({e})");
            println!("  --force: dismounting the volume instead; open files on this drive lose their handles");
            vol.dismount()
        }
        Err(e) => Err(format!(
            "{e}. Something has this drive open (an Explorer window showing it, the disk editor, \
             a shell inside it). Close it and retry, or add --force to dismount the drive instead."
        )),
    }
}

/// Make sure we can take the volume BEFORE we delete anything.
fn preflight(drive: char, force: bool) -> Result<(), String> {
    let vol = Volume::open(drive, true)?;
    acquire_volume(&vol, force) // dropping the handle releases the lock
}

/// Remove the (already wiped) file through NTFS, then scrub what NTFS leaves in the freed record.
pub fn delete_and_scrub(
    drive: char,
    path: &str,
    rec_off: u64,
    record_number: u64,
    record_size: usize,
    force: bool,
) -> Result<(), String> {
    println!("Finishing     :");
    preflight(drive, force)?;
    delete_with_retry(path)?;
    println!("  file deleted through the file system (not moved to the Recycle Bin)");

    scrub_record(drive, rec_off, record_number, record_size, force).map_err(|e| {
        format!(
            "{e}\n  The file is deleted and its data wiped, but the freed MFT record was NOT scrubbed.\n  \
             Fix the problem, then run:  e-shredder --scrub-record {drive}: {record_number}"
        )
    })
}

/// Cleanup mode: scrub an already-freed MFT record, addressed by number.
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
    vol.flush()?; // make sure NTFS's own pending changes are on disk before we look

    let mut rec = read_record(&vol, rec_off, record_size)?;
    let own_number = u32::from_le_bytes(rec[0x2C..0x30].try_into().unwrap()) as u64;
    let flags = u16::from_le_bytes([rec[0x16], rec[0x17]]);
    if own_number != record_number {
        return Err(format!("record at 0x{rec_off:X} is #{own_number}, expected #{record_number}; nothing written"));
    }
    if flags & 0x01 != 0 {
        return Err("the MFT record is marked in use (not yet written by NTFS, or reused); nothing written".into());
    }
    println!("  MFT record #{record_number} is marked free on disk (in-use flag cleared by NTFS)");

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

    // Read it back and make sure nothing is left
    let check = read_record(&vol, rec_off, record_size)?;
    let p = parse_record(&check)?;
    if p.in_use || !p.file_names.is_empty() || !p.streams.is_empty() {
        return Err("verification failed: remnants still present in the record".into());
    }
    println!("  freed MFT record scrubbed and verified (no name, no data left)");

    vol.dismount()?; // drop cached copies; the volume remounts on next access
    Ok(())
}