mod finish;
mod mft;
mod shell;
mod wipe;
mod win;


use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

use finish::*;
use mft::*;
use shell::*;
use wipe::*;
use win::*;


static PAUSE: AtomicBool = AtomicBool::new(false);


    if PAUSE.load(Ordering::Relaxed) {
        print!("\nPress Enter to close this window...");
        // `print!` has no newline, so the text may sit in a buffer; flush shows it now.
        io::stdout().flush().ok();
        // Read (and discard) one line: returns when the user presses Enter.
        let mut s = String::new();
        io::stdin().read_line(&mut s).ok();
    }
}

/// Print an error message and terminate the program with exit code 1.
/// The return type `!` ("never") tells the compiler this function never returns. That lets it
/// be used inside `unwrap_or_else(|e| die(&e))`, where a value of any type is expected: since
/// `die` never returns, no value is needed. It calls `pause()` first so the message stays
/// visible when the window would otherwise close.
fn die(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    pause();
    process::exit(1);
}

/// One stream of the file whose data lives in clusters and must be wiped.
/// It is built in `erase` from the parsed MFT record. The lifetime `'a` says that `runs`
/// borrows from the parsed record, which therefore must outlive the `Target`.
struct Target<'a> {
    /// Human-readable name for messages: "(default)" or the alternate stream's name.
    label: String,
    /// What to open to read this stream through the normal API: the path, or `path:stream`.
    spec: String, // what to open to read this stream through the normal API
    runs: &'a [Run],
    real_size: u64,
}

/// Verify, plan and (when `do_erase`) wipe the data of the file.

/// Deleting the file and scrubbing the record happen afterwards in `finish.rs`.
#[allow(clippy::too_many_arguments)]
fn erase(
    vol: &Volume,
    path: &str,
    file_name: &str,
    p: &ParsedRecord,
    rec: &[u8],
    cs: u64,
    do_erase: bool,
    yes: bool,
    force: bool,
) -> Result<(), String> {
    println!("Erase plan    :");

    // The streams that have clusters to wipe (resident streams need no cluster wiping).
    let mut targets: Vec<Target> = Vec::new();
    for s in &p.streams {
        // A readable label for messages.
        let label = if s.name.is_empty() { "(default)".to_string() } else { s.name.clone() };
        // Compressed, sparse or encrypted streams do not store plain file bytes in their
        // clusters, so overwriting them this way would not be reliable (and our verification
        // would not apply). Refuse them rather than give a false sense of security.
        if s.flags != 0 {
            return Err(format!("stream {label} is compressed/sparse/encrypted; refusing"));
        }
        // How to open this stream with the normal API: the plain path for the main stream,
        // `path:streamname` for an alternate data stream.
        let spec = if s.name.is_empty() { path.to_string() } else { format!("{path}:{}", s.name) };
        match &s.kind {
            // Small file: its bytes are inside the MFT record. There are no clusters, so the
            // only check possible is that the bytes in the record equal what Windows returns.
            DataKind::Resident { record_offset, length } => {
                let via_fs = std::fs::read(&spec).map_err(|e| format!("cannot read '{spec}': {e}"))?;
                if via_fs[..] != rec[*record_offset..*record_offset + *length] {
                    return Err("MISMATCH: resident data differs from the file contents".into());
                }
                println!("  stream {label}: resident ({length} bytes in the MFT record) matches the file contents");
            }
            // Large file: remember it for wiping.
            DataKind::NonResident { runs, real_size, .. } => {
                targets.push(Target { label, spec, runs, real_size: *real_size });
            }
        }
    }

    // Prove the runs are right before touching anything. `verify_runs` compares the raw
    // clusters with the file as read through Windows and fails on any difference.
    for t in &targets {
        print!("  verifying stream {} against the raw clusters ... ", t.label);
        io::stdout().flush().ok();
        verify_runs(vol, &t.spec, t.runs, cs, t.real_size)?;
        println!("OK ({} bytes identical)", t.real_size);
    }

    // Print the plan so the user (and the log) can see exactly what will be overwritten.
    if targets.is_empty() {
        println!("  no data stored in clusters (resident data only)");
    } else {
        // Sum of clusters over all runs of all streams.
        let total_clusters: u64 = targets.iter().flat_map(|t| t.runs.iter()).map(|r| r.clusters).sum();
        println!("  plan: {} clusters ({} bytes), passes: {:?}", total_clusters, total_clusters * cs, PASSES);
        for t in &targets {
            for (i, r) in t.runs.iter().enumerate() {
                // Volume byte offset = start cluster * cluster size; length = clusters * size.
                println!(
                    "    {} run {i}: volume offset 0x{:X}, {} bytes",
                    t.label,
                    r.lcn * cs,
                    r.clusters * cs
                );
            }
        }
    }
    println!("  then: delete via the file system, lock the volume, scrub the freed MFT record");

    // Dry run: everything above was read-only; stop before any write.
    if !do_erase {
        println!("DRY RUN - nothing was written. Add --erase to perform it.");
        return Ok(());
    }

    // The destruction is irreversible, so require the user to type ERASE (unless `--yes`).
    if !yes {
        print!("Type ERASE to permanently destroy '{file_name}': ");
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
        if line.trim() != "ERASE" {
            return Err("confirmation not given; nothing was written".into());
        }
    }

    // The wiping itself, only if there are clusters to wipe.
    if !targets.is_empty() {
        // Lock (or, as fallback, dismount) the volume: Windows only allows raw writes then.
        acquire_volume(vol, force)?;
        println!("  volume secured, wiping...");
        for t in &targets {
            // Overwrite every cluster of the stream with the patterns in PASSES...
            wipe_runs(vol, t.runs, cs, &PASSES)?;
            // ...then read it back and confirm it is all zero.
            verify_zeroed(vol, t.runs, cs)?;
            println!("  stream {}: wiped and verified (all zero)", t.label);
        }
        // Drop Windows' cached view so stale file data cannot be shown or written back.
        let _ = vol.dismount(); // may already be dismounted by the --force fallback; ignore that
    }
    Ok(())
}

/// Program entry point: command-line handling, then the flowchart from top to bottom.
fn main() {
    // All command-line arguments; element 0 is the program's own path.
    let raw: Vec<String> = env::args().collect();
    // `--pause` is an internal flag; note it, then remove it so the rest of the code can treat
    // the remaining arguments uniformly.
    let pause_flag = raw.iter().any(|a| a == "--pause");
    let argv: Vec<String> = raw.into_iter().filter(|a| a != "--pause").collect();

    // Default: if the volume can't be locked (Explorer keeps handles on it), dismount it.
    // --strict turns that off and fails with an error instead.
    // (Variable name `force` is historical: `true` means "fall back to dismount".)
    let force = !argv.iter().any(|a| a == "--strict");

    // No arguments at all: show the usage text and quit. (`argv[0]` is the program itself.)
    if argv.len() < 2 {
        eprintln!(
            "Usage:\n  e-shredder <file> [--erase] [--yes] [--strict]\n  \
             e-shredder --install | --uninstall\n  \
             e-shredder --scrub-record <drive>: <record number> [--strict]"
        );
        process::exit(1);
    }

    // Context-menu registration: per-user registry, no elevation needed
    // This is handled BEFORE the elevation check on purpose: writing under HKEY_CURRENT_USER
    // needs no Administrator rights, so no UAC prompt should appear for it.
    match argv[1].as_str() {
        "--install" => {
            // Flowchart step 7: add the action to the right-click menu.
            match install(false) {
                Ok(cmd) => println!(
                    "Context menu entry installed.\nCommand: {cmd}\n\
                     Right-click a file (Windows 11: 'Show more options', or Shift+right-click)."
                ),
                Err(e) => die(&e),
            }
            return;
        }
        "--uninstall" => {
            match uninstall() {
                Ok(true) => println!("Context menu entry removed."),
                Ok(false) => println!("Context menu entry was not installed."),
                Err(e) => die(&e),
            }
            return;
        }
        // Anything else continues below.
        _ => {}
    }

    // Everything below needs Administrator rights (raw volume access): relaunch if needed
    if !is_elevated() {
        // Pass the same arguments to the elevated copy, plus `--pause` because it will run in
        // a new console window that would close immediately otherwise.
        let mut child: Vec<String> = argv[1..].to_vec();
        child.push("--pause".into());
        match relaunch_elevated(&child) {
            Ok(()) => println!("Relaunched with Administrator rights in a new window."),
            Err(e) => die(&e),
        }
        // This (unelevated) copy has done its job.
        return;
    }
    // From here on we are elevated. Remember whether the window must be kept open at the end.
    if pause_flag {
        PAUSE.store(true, Ordering::Relaxed);
    }

    // Cleanup mode: e-shredder --scrub-record X: 50
    if argv[1] == "--scrub-record" {
        // Keep only the two positional arguments (drive letter and record number); the
        // option flags are not part of them.
        let rest: Vec<&String> = argv[2..].iter().filter(|a| !matches!(a.as_str(), "--force" | "--strict")).collect();
        if rest.len() != 2 {
            die("usage: e-shredder --scrub-record <drive letter>: <record number>");
        }
        // First character of "X:" is the drive letter.
        let drive = rest[0].chars().next().unwrap_or('?').to_ascii_uppercase();
        if !drive.is_ascii_alphabetic() {
            die("invalid drive letter");
        }
        let n: u64 = rest[1].parse().unwrap_or_else(|_| die("record number must be a decimal number"));
        if let Err(e) = scrub_by_number(drive, n, force) {
            die(&e);
        }
        println!("Done.");
        pause();
        return;
    }

    // 1. Read the file path (and flags) from the command line
    // FLOWCHART: "Application reads the <File Path> from command line arguments".
    let mut path_arg: Option<String> = None;
    let mut do_erase = false;
    let mut yes = false;
    for a in argv.iter().skip(1) {
        match a.as_str() {
            "--erase" => do_erase = true,
            "--yes" => yes = true,
            // Accepted but ignored: `force` was already decided above.
            "--force" | "--strict" => {}
            // Any other word starting with `--` is a mistake: stop instead of guessing.
            s if s.starts_with("--") => die(&format!("unknown option {s}")),
            // Anything else is taken as the file path.
            other => path_arg = Some(other.to_string()),
        }
    }
    let path_arg = path_arg.unwrap_or_else(|| die("no file path given"));

    // 2. Check that the file exists
    // FLOWCHART: "uses Rust filesystem API to check for the existence of the file".
    // `is_file` is false for missing paths and for directories; this tool handles files only.
    let path = Path::new(&path_arg);
    if !path.is_file() {
        die(&format!("file '{path_arg}' does not exist."));
    }
    // Turn a possibly relative path into a full absolute one (needed for the drive letter).
    let full = std::fs::canonicalize(path).unwrap_or_else(|e| die(&format!("cannot resolve path: {e}")));
    let full_str = full.to_string_lossy().to_string();
    // `canonicalize` returns the `\\?\X:\...` form; strip that prefix for a plain `X:\...` path.
    let plain = full_str.strip_prefix(r"\\?\").unwrap_or(&full_str).to_string();
    // Position 1 of "X:\..." must be ':' - this rejects network (UNC) paths, which have no
    // local volume that we could open raw.
    if plain.as_bytes().get(1) != Some(&b':') {
        die("only local drive-letter paths are supported.");
    }
    // The drive letter selects which volume to open (`\\.\X:`).
    let drive = plain.chars().next().unwrap().to_ascii_uppercase();
    // Only the file name part, used for the identity check and the confirmation prompt.
    let file_name = Path::new(&plain).file_name().unwrap().to_string_lossy().to_string();
    println!("File          : {plain}");

    // Step 1: MFT record number
    // The 64-bit file reference is split: low 48 bits = record number, high 16 = sequence.
    let file_ref = get_file_reference(&plain).unwrap_or_else(|e| die(&e));
    let record_number = file_ref & 0x0000_FFFF_FFFF_FFFF;
    let sequence = (file_ref >> 48) as u16;
    println!("MFT record    : {record_number} (0x{record_number:X}), sequence {sequence}");

    // Step 2: open the volume (read+write only when erasing), boot sector, MFT
    // A dry run opens the volume read-only so it cannot change anything.
    let vol = Volume::open(drive, do_erase).unwrap_or_else(|e| die(&e));
    // Sector 0 of the volume is the NTFS boot sector (512 bytes).
    let mut boot = [0u8; 512];
    vol.read_at(0, &mut boot).unwrap_or_else(|e| die(&e));
    let b = parse_boot_sector(&boot).unwrap_or_else(|e| die(&e));
    // Cluster size as u64, used in every LCN -> byte-offset conversion below.
    let cs = b.cluster_size as u64;
    println!(
        "Cluster size  : {} bytes, sector size: {} bytes, record size: {} bytes",
        b.cluster_size, b.bytes_per_sector, b.record_size
    );

    // Read the MFT's own run list (it can be fragmented) so any record can be located.
    let mft_runs = load_mft_runs(&vol, &b).unwrap_or_else(|e| die(&e));
    println!("MFT data runs : {}", mft_runs.len());

    // Steps 3 + 4: read and parse the record
    // Position of our file's record on the volume, then read and parse it.
    let rec_off = mft_record_offset(&mft_runs, cs, b.record_size as u64, record_number)
        .unwrap_or_else(|| die("record number lies outside the MFT"));
    println!("Record offset : 0x{rec_off:X}");
    let rec = read_record(&vol, rec_off, b.record_size as usize).unwrap_or_else(|e| die(&e));
    let p = parse_record(&rec).unwrap_or_else(|e| die(&e));

    // Safety checks
    // These make it very unlikely that the wrong record (and so the wrong file) is erased.
    println!("Safety checks :");
    // Becomes false as soon as one check fails.
    let mut all_ok = true;
    // A small closure that prints OK/FAIL for one check and folds the result into `all_ok`.
    let mut check = |label: &str, cond: bool| {
        println!("  [{}] {label}", if cond { "OK" } else { "FAIL" });
        all_ok &= cond;
    };
    // The record must say it is the record we asked for...
    check("record's own number matches", p.record_number as u64 == record_number);
    // ...with the same sequence number as the file reference (not a reused record)...
    check("sequence number matches", p.sequence == sequence);
    // ...it must currently be in use, and be a file...
    check("record is in use", p.in_use);
    check("record is not a directory", !p.is_directory);
    // ...carry the file name the user gave (case-insensitive, as NTFS names are)...
    check(
        "a $FILE_NAME matches the requested name",
        p.file_names.iter().any(|n| n.to_lowercase() == file_name.to_lowercase()),
    );
    // ...and not use the unsupported attribute-list feature.
    check("no $ATTRIBUTE_LIST (unsupported for now)", !p.has_attribute_list);
    if !all_ok {
        die("safety checks failed - refusing to continue.");
    }
    if p.hard_links > 1 {
        println!("  Note: {} hard links point at this data", p.hard_links);
    }
    println!("File names    : {:?}", p.file_names);

    // Report where the data lives
    // For every stream, print where its data is: inside the record (resident) or the list of
    // runs (non-resident). This is the output to compare against `fsutil file queryextents`
    // or a disk editor, as the assignment requires.
    for s in &p.streams {
        let label = if s.name.is_empty() { "(default)".to_string() } else { s.name.clone() };
        println!("Stream {label}, attribute flags 0x{:04X}", s.flags);
        match &s.kind {
            DataKind::Resident { record_offset, length } => {
                // Volume position of the data = record position + position inside the record.
                println!(
                    "  RESIDENT: {length} bytes inside the MFT record, at volume offset 0x{:X}",
                    rec_off + *record_offset as u64
                );
            }
            DataKind::NonResident { runs, real_size, allocated_size } => {
                println!("  NON-RESIDENT: real size {real_size}, allocated {allocated_size}");
                // VCN of the first cluster of each run: the runs follow each other in file
                // order, so it is the sum of the lengths of the runs before.
                let mut vcn = 0u64;
                for (i, r) in runs.iter().enumerate() {
                    if r.sparse {
                        println!("  Run {i}: VCN 0x{vcn:X}, {} clusters, SPARSE", r.clusters);
                    } else {
                        println!(
                            "  Run {i}: VCN 0x{vcn:X}, {} clusters (0x{:X}), LCN 0x{:X}, volume offset 0x{:X}",
                            r.clusters, r.clusters, r.lcn, r.lcn * cs
                        );
                    }
                    vcn += r.clusters;
                }
            }
        }
    }

    // Stage 3: verify, then wipe the data clusters
    if let Err(e) = erase(&vol, &plain, &file_name, &p, &rec, cs, do_erase, yes, force) {
        die(&e);
    }

    // Stage 4: delete through NTFS, then scrub the freed MFT record
    if do_erase {
        drop(vol); // release the (dismounted) volume handle before using the file system again
        if let Err(e) = delete_and_scrub(drive, &plain, rec_off, record_number, b.record_size as usize, force) {
            die(&e);
        }
        println!("Done. '{file_name}' is wiped and deleted.");
    }
    // Keep the window open if we were started from the context menu.
    pause();
}
