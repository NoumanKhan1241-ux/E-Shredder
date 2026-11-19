mod mft;
mod wipe;
mod win;

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process;

use mft::*;
use wipe::*;
use win::*;

fn die(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    process::exit(1);
}

struct Target<'a> {
    label: String,
    spec: String, // what to open to read this stream through the normal API
    runs: &'a [Run],
    real_size: u64,
}

fn erase(
    vol: &Volume,
    path: &str,
    file_name: &str,
    p: &ParsedRecord,
    cs: u64,
    do_erase: bool,
    yes: bool,
) -> Result<(), String> {
    println!("Erase plan    :");

    // Collect the streams whose data lives in clusters
    let mut targets: Vec<Target> = Vec::new();
    for s in &p.streams {
        let label = if s.name.is_empty() { "(default)".to_string() } else { s.name.clone() };
        if s.flags != 0 {
            return Err(format!("stream {label} is compressed/sparse/encrypted; refusing"));
        }
        match &s.kind {
            DataKind::Resident { .. } => {
                println!("  stream {label}: resident (inside the MFT record) - handled in the next stage");
            }
            DataKind::NonResident { runs, real_size, .. } => {
                let spec = if s.name.is_empty() { path.to_string() } else { format!("{path}:{}", s.name) };
                targets.push(Target { label, spec, runs, real_size: *real_size });
            }
        }
    }
    if targets.is_empty() {
        println!("  nothing stored in clusters; nothing to do in this stage.");
        return Ok(());
    }

    // Prove the runs are right before touching anything
    for t in &targets {
        print!("  verifying stream {} against the raw clusters ... ", t.label);
        io::stdout().flush().ok();
        verify_runs(vol, &t.spec, t.runs, cs, t.real_size)?;
        println!("OK ({} bytes identical)", t.real_size);
    }

    let total_clusters: u64 = targets.iter().flat_map(|t| t.runs.iter()).map(|r| r.clusters).sum();
    println!(
        "  plan: {} clusters ({} bytes), passes: {:?}",
        total_clusters,
        total_clusters * cs,
        PASSES
    );
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

    if !do_erase {
        println!("DRY RUN - nothing was written. Add --erase to perform it.");
        return Ok(());
    }

    if !yes {
        print!("Type ERASE to permanently destroy the data of '{file_name}': ");
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
        if line.trim() != "ERASE" {
            return Err("confirmation not given; nothing was written".into());
        }
    }

    vol.lock().map_err(|e| {
        format!(
            "{e}. Close anything that has this drive open (Explorer windows, shells whose \
             current directory is on it, the disk editor's volume tab) and try again."
        )
    })?;
    println!("  volume locked, wiping...");

    for t in &targets {
        wipe_runs(vol, t.runs, cs, &PASSES)?;
        verify_zeroed(vol, t.runs, cs)?;
        println!("  stream {}: wiped and verified (all zero)", t.label);
    }

    vol.dismount()?; // forget cached data; the volume remounts on next access
    println!("Done. Data clusters are wiped. (The file entry itself still exists: next stage.)");
    Ok(())
}

fn main() {
    // 1. Read the file path (and flags) from the command line
    let mut path_arg: Option<String> = None;
    let mut do_erase = false;
    let mut yes = false;
    for a in env::args().skip(1) {
        match a.as_str() {
            "--erase" => do_erase = true,
            "--yes" => yes = true,
            s if s.starts_with("--") => die(&format!("unknown option {s}")),
            other => path_arg = Some(other.to_string()),
        }
    }
    let path_arg = path_arg.unwrap_or_else(|| {
        eprintln!("Usage: e-shredder <file path> [--erase] [--yes]");
        process::exit(1);
    });

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
    let vol = Volume::open(drive, do_erase).unwrap_or_else(|e| die(&format!("{e}. Run as Administrator.")));
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

    // Stage 3: verify + erase the data clusters
    if let Err(e) = erase(&vol, &plain, &file_name, &p, cs, do_erase, yes) {
        die(&e);
    }
}