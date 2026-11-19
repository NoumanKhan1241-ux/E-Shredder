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

/// Set when launched from the context menu: the console closes on exit, so wait for Enter.
static PAUSE: AtomicBool = AtomicBool::new(false);

fn pause() {
    if PAUSE.load(Ordering::Relaxed) {
        print!("\nPress Enter to close this window...");
        io::stdout().flush().ok();
        let mut s = String::new();
        io::stdin().read_line(&mut s).ok();
    }
}

fn die(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    pause();
    process::exit(1);
}

struct Target<'a> {
    label: String,
    spec: String, // what to open to read this stream through the normal API
    runs: &'a [Run],
    real_size: u64,
}

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

    let mut targets: Vec<Target> = Vec::new();
    for s in &p.streams {
        let label = if s.name.is_empty() { "(default)".to_string() } else { s.name.clone() };
        if s.flags != 0 {
            return Err(format!("stream {label} is compressed/sparse/encrypted; refusing"));
        }
        let spec = if s.name.is_empty() { path.to_string() } else { format!("{path}:{}", s.name) };
        match &s.kind {
            DataKind::Resident { record_offset, length } => {
                let via_fs = std::fs::read(&spec).map_err(|e| format!("cannot read '{spec}': {e}"))?;
                if via_fs[..] != rec[*record_offset..*record_offset + *length] {
                    return Err("MISMATCH: resident data differs from the file contents".into());
                }
                println!("  stream {label}: resident ({length} bytes in the MFT record) matches the file contents");
            }
            DataKind::NonResident { runs, real_size, .. } => {
                targets.push(Target { label, spec, runs, real_size: *real_size });
            }
        }
    }

    for t in &targets {
        print!("  verifying stream {} against the raw clusters ... ", t.label);
        io::stdout().flush().ok();
        verify_runs(vol, &t.spec, t.runs, cs, t.real_size)?;
        println!("OK ({} bytes identical)", t.real_size);
    }

    if targets.is_empty() {
        println!("  no data stored in clusters (resident data only)");
    } else {
        let total_clusters: u64 = targets.iter().flat_map(|t| t.runs.iter()).map(|r| r.clusters).sum();
        println!("  plan: {} clusters ({} bytes), passes: {:?}", total_clusters, total_clusters * cs, PASSES);
        for t in &targets {
            for (i, r) in t.runs.iter().enumerate() {
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

    if !do_erase {
        println!("DRY RUN - nothing was written. Add --erase to perform it.");
        return Ok(());
    }

    if !yes {
        print!("Type ERASE to permanently destroy '{file_name}': ");
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
        if line.trim() != "ERASE" {
            return Err("confirmation not given; nothing was written".into());
        }
    }

    if !targets.is_empty() {
        acquire_volume(vol, force)?;
        println!("  volume secured, wiping...");
        for t in &targets {
            wipe_runs(vol, t.runs, cs, &PASSES)?;
            verify_zeroed(vol, t.runs, cs)?;
            println!("  stream {}: wiped and verified (all zero)", t.label);
        }
        let _ = vol.dismount(); // may already be dismounted by the --force fallback; ignore that
    }
    Ok(())
}

fn main() {
    let raw: Vec<String> = env::args().collect();
    let pause_flag = raw.iter().any(|a| a == "--pause");
    let argv: Vec<String> = raw.into_iter().filter(|a| a != "--pause").collect();

    // Default: if the volume can't be locked (Explorer keeps handles on it), dismount it.
    // --strict turns that off and fails with an error instead.
    let force = !argv.iter().any(|a| a == "--strict");

    if argv.len() < 2 {
        eprintln!(
            "Usage:\n  e-shredder <file> [--erase] [--yes] [--strict]\n  \
             e-shredder --install | --uninstall\n  \
             e-shredder --scrub-record <drive>: <record number> [--strict]"
        );
        process::exit(1);
    }

    // Context-menu registration: per-user registry, no elevation needed
    match argv[1].as_str() {
        "--install" => {
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
        _ => {}
    }

    // Everything below needs Administrator rights (raw volume access): relaunch if needed
    if !is_elevated() {
        let mut child: Vec<String> = argv[1..].to_vec();
        child.push("--pause".into());
        match relaunch_elevated(&child) {
            Ok(()) => println!("Relaunched with Administrator rights in a new window."),
            Err(e) => die(&e),
        }
        return;
    }
    if pause_flag {
        PAUSE.store(true, Ordering::Relaxed);
    }

    // Cleanup mode: e-shredder --scrub-record X: 50
    if argv[1] == "--scrub-record" {
        let rest: Vec<&String> = argv[2..].iter().filter(|a| !matches!(a.as_str(), "--force" | "--strict")).collect();
        if rest.len() != 2 {
            die("usage: e-shredder --scrub-record <drive letter>: <record number>");
        }
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
    let mut path_arg: Option<String> = None;
    let mut do_erase = false;
    let mut yes = false;
    for a in argv.iter().skip(1) {
        match a.as_str() {
            "--erase" => do_erase = true,
            "--yes" => yes = true,
            "--force" | "--strict" => {}
            s if s.starts_with("--") => die(&format!("unknown option {s}")),
            other => path_arg = Some(other.to_string()),
        }
    }
    let path_arg = path_arg.unwrap_or_else(|| die("no file path given"));

    // 2. Check that the file exists
    let path = Path::new(&path_arg);
    if !path.is_file() {
        die(&format!("file '{path_arg}' does not exist."));
    }
    let full = std::fs::canonicalize(path).unwrap_or_else(|e| die(&format!("cannot resolve path: {e}")));
    let full_str = full.to_string_lossy().to_string();
    let plain = full_str.strip_prefix(r"\\?\").unwrap_or(&full_str).to_string();
    if plain.as_bytes().get(1) != Some(&b':') {
        die("only local drive-letter paths are supported.");
    }
    let drive = plain.chars().next().unwrap().to_ascii_uppercase();
    let file_name = Path::new(&plain).file_name().unwrap().to_string_lossy().to_string();
    println!("File          : {plain}");

    // Step 1: MFT record number
    let file_ref = get_file_reference(&plain).unwrap_or_else(|e| die(&e));
    let record_number = file_ref & 0x0000_FFFF_FFFF_FFFF;
    let sequence = (file_ref >> 48) as u16;
    println!("MFT record    : {record_number} (0x{record_number:X}), sequence {sequence}");

    // Step 2: open the volume (read+write only when erasing), boot sector, MFT
    let vol = Volume::open(drive, do_erase).unwrap_or_else(|e| die(&e));
    let mut boot = [0u8; 512];
    vol.read_at(0, &mut boot).unwrap_or_else(|e| die(&e));
    let b = parse_boot_sector(&boot).unwrap_or_else(|e| die(&e));
    let cs = b.cluster_size as u64;
    println!(
        "Cluster size  : {} bytes, sector size: {} bytes, record size: {} bytes",
        b.cluster_size, b.bytes_per_sector, b.record_size
    );

    let mft_runs = load_mft_runs(&vol, &b).unwrap_or_else(|e| die(&e));
    println!("MFT data runs : {}", mft_runs.len());

    // Steps 3 + 4: read and parse the record
    let rec_off = mft_record_offset(&mft_runs, cs, b.record_size as u64, record_number)
        .unwrap_or_else(|| die("record number lies outside the MFT"));
    println!("Record offset : 0x{rec_off:X}");
    let rec = read_record(&vol, rec_off, b.record_size as usize).unwrap_or_else(|e| die(&e));
    let p = parse_record(&rec).unwrap_or_else(|e| die(&e));

    // Safety checks
    println!("Safety checks :");
    let mut all_ok = true;
    let mut check = |label: &str, cond: bool| {
        println!("  [{}] {label}", if cond { "OK" } else { "FAIL" });
        all_ok &= cond;
    };
    check("record's own number matches", p.record_number as u64 == record_number);
    check("sequence number matches", p.sequence == sequence);
    check("record is in use", p.in_use);
    check("record is not a directory", !p.is_directory);
    check(
        "a $FILE_NAME matches the requested name",
        p.file_names.iter().any(|n| n.to_lowercase() == file_name.to_lowercase()),
    );
    check("no $ATTRIBUTE_LIST (unsupported for now)", !p.has_attribute_list);
    if !all_ok {
        die("safety checks failed - refusing to continue.");
    }
    if p.hard_links > 1 {
        println!("  Note: {} hard links point at this data", p.hard_links);
    }
    println!("File names    : {:?}", p.file_names);

    // Report where the data lives
    for s in &p.streams {
        let label = if s.name.is_empty() { "(default)".to_string() } else { s.name.clone() };
        println!("Stream {label}, attribute flags 0x{:04X}", s.flags);
        match &s.kind {
            DataKind::Resident { record_offset, length } => {
                println!(
                    "  RESIDENT: {length} bytes inside the MFT record, at volume offset 0x{:X}",
                    rec_off + *record_offset as u64
                );
            }
            DataKind::NonResident { runs, real_size, allocated_size } => {
                println!("  NON-RESIDENT: real size {real_size}, allocated {allocated_size}");
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
    pause();
}