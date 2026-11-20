
use crate::win::Volume;

pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;

pub const ATTR_DATA: u32 = 0x80;

const ATTR_END: u32 = 0xFFFF_FFFF;


/// Read a 16-bit little-endian unsigned number from `b` at offset `o`.
fn u16_at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
/// Read a 32-bit little-endian unsigned number from `b` at offset `o`.
/// (`try_into` converts the 4-byte slice into the fixed-size array `from_le_bytes` needs.)
fn u32_at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
/// Read a 64-bit little-endian unsigned number from `b` at offset `o`.
fn u64_at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
/// Decode UTF-16LE bytes (how NTFS stores file and stream names) into a Rust `String`.
fn utf16(b: &[u8]) -> String {
    // Group the bytes in pairs and turn every pair into one 16-bit character.
    let v: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    // `lossy`: invalid sequences become a replacement character instead of failing.
    String::from_utf16_lossy(&v)
}

pub struct BootInfo {
    pub bytes_per_sector: u32,
    pub cluster_size: u32,
    pub record_size: u32,
    pub mft_cluster: u64,
}


pub fn parse_boot_sector(s: &[u8]) -> Result<BootInfo, String> {
    if &s[3..11] != b"NTFS    " {
        return Err("not an NTFS volume (OEM ID is not 'NTFS')".into());
    }
    let bytes_per_sector = u16_at(s, 0x0B) as u32;
    let cluster_size = bytes_per_sector * s[0x0D] as u32;
    let mft_cluster = u64_at(s, 0x30);
    let raw = s[0x40] as i8;
    let record_size = if raw > 0 { raw as u32 * cluster_size } else { 1u32 << (-(raw as i32)) };
    Ok(BootInfo { bytes_per_sector, cluster_size, record_size, mft_cluster })
}


/// One contiguous piece of a file's data on the volume.
#[derive(Debug, Clone)]
pub struct Run {
    pub lcn: u64,      // start cluster on the volume (meaningless if sparse)
    pub clusters: u64, // length in clusters
    pub sparse: bool,  // hole: no clusters are actually allocated
}


/// The offsets are *relative* (each is added to the previous run's start) and *signed*, so a
/// later fragment may lie before an earlier one on the disk, as in the example. Getting this
/// sign wrong is the classic bug, which is why the sign extension below exists.
pub fn decode_runs(data: &[u8]) -> Result<Vec<Run>, String> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    // Signed (i64) because the deltas can be negative.
    let mut lcn: i64 = 0;

    while pos < data.len() {
        // The header byte describes the sizes of the two fields that follow.
        let header = data[pos];
        // A zero header byte is the terminator of the run list.
        if header == 0 {
            break;
        }
        pos += 1;
        let len_size = (header & 0x0F) as usize;
        let off_size = (header >> 4) as usize;
    
        if len_size == 0 || len_size > 8 || off_size > 8 || pos + len_size + off_size > data.len() {
            return Err(format!("corrupt run list (header 0x{header:02X})"));
        }

        // Read the length field (little-endian, variable width) byte by byte.
        let mut clusters: u64 = 0;
        for i in 0..len_size {
            clusters |= (data[pos + i] as u64) << (8 * i);
        }
        pos += len_size;

        // An offset size of 0 means "no clusters are stored": a sparse run (a hole).
        if off_size == 0 {
            runs.push(Run { lcn: 0, clusters, sparse: true });
            continue;
        }

        // Read the offset field (little-endian, variable width) into a signed number.
        let mut delta: i64 = 0;
        for i in 0..off_size {
            delta |= (data[pos + i] as i64) << (8 * i);
        }
       
        if off_size < 8 && data[pos + off_size - 1] & 0x80 != 0 {
            delta |= -1i64 << (8 * off_size); // sign-extend
        }
        pos += off_size;

        lcn += delta;
        if lcn < 0 {
            return Err("run list points before the start of the volume".into());
        }
        runs.push(Run { lcn: lcn as u64, clusters, sparse: false });
    }
    Ok(runs)
}


/// Modifies `rec` in place; returns an error if the record is not a valid `FILE` record or if
/// a sector's check value does not match (torn or corrupt record).
pub fn apply_fixups(rec: &mut [u8]) -> Result<(), String> {
    if rec.len() < 0x30 || &rec[0..4] != b"FILE" {
        return Err("record does not start with 'FILE'".into());
    }
    let usa_off = u16_at(rec, 4) as usize;
    let usa_cnt = u16_at(rec, 6) as usize;
    if usa_cnt < 2 || usa_off + usa_cnt * 2 > rec.len() || (usa_cnt - 1) * 512 > rec.len() {
        return Err("invalid update sequence array".into());
    }
    let usn = [rec[usa_off], rec[usa_off + 1]];
    for i in 1..usa_cnt {
        
        let end = i * 512 - 2;
        // The check value stored there must equal the USN, otherwise the write was torn.
        if rec[end..end + 2] != usn {
            return Err(format!("fixup mismatch in sector {i} (torn or corrupt record)"));
        }
        // Put the real bytes (saved in the USA) back where they belong.
        rec[end] = rec[usa_off + i * 2];
        rec[end + 1] = rec[usa_off + i * 2 + 1];
    }
    Ok(())
}

/// Where the data of one stream lives.
pub enum DataKind {
    
    Resident { record_offset: usize, length: usize },
    
    NonResident { runs: Vec<Run>, real_size: u64, allocated_size: u64 },
}

pub struct DataStream {
    pub name: String, // empty = the normal unnamed stream; otherwise an alternate data stream
    pub flags: u16,   // 0x0001 compressed, 0x4000 encrypted, 0x8000 sparse
    pub kind: DataKind,
}

pub struct ParsedRecord {
    
    pub record_number: u32,
    pub sequence: u16,
    pub in_use: bool,
    pub is_directory: bool,
    pub hard_links: u16,
    pub file_names: Vec<String>,
    pub streams: Vec<DataStream>,
    pub has_attribute_list: bool,
}


/// Each attribute starts with a header: `0x00` type (u32), `0x04` total length (u32),
/// `0x08` non-resident flag (u8), `0x09` name length in characters (u8), `0x0A` name offset
/// (u16), `0x0C` flags (u16). After that the layout differs for resident and non-resident
/// attributes (see the code).
pub fn parse_record(rec: &[u8]) -> Result<ParsedRecord, String> {
    // Read the header fields we need (offsets are given in the doc comment above).
    let sequence = u16_at(rec, 0x10);
    let hard_links = u16_at(rec, 0x12);
    let first_attr = u16_at(rec, 0x14) as usize;
    let flags = u16_at(rec, 0x16);
    let used = u32_at(rec, 0x18) as usize;
    let base_ref = u64_at(rec, 0x20);
    let record_number = u32_at(rec, 0x2C);

    if base_ref != 0 {
        return Err("this is an extension record, not a base record".into());
    }
   
    if used > rec.len() || first_attr + 8 > used {
        return Err("invalid record header".into());
    }

    // Build the result with the header information; the lists are filled in the loop below.
    let mut out = ParsedRecord {
        record_number,
        sequence,
        in_use: flags & 0x01 != 0,
        is_directory: flags & 0x02 != 0,
        hard_links,
        file_names: Vec::new(),
        streams: Vec::new(),
        has_attribute_list: false,
    };

    // `pos` is the offset of the attribute currently being examined.
    let mut pos = first_attr;
    while pos + 8 <= used {
        let atype = u32_at(rec, pos);
        if atype == ATTR_END {
            break;
        }
        let alen = u32_at(rec, pos + 4) as usize;
       
        if alen < 0x18 || alen % 8 != 0 || pos + alen > used {
            return Err(format!("invalid attribute length {alen} at record offset 0x{pos:X}"));
        }
        let attr = &rec[pos..pos + alen];
        let non_resident = attr[8] != 0;
        let name_len = attr[9] as usize;
        let name_off = u16_at(attr, 0x0A) as usize;
        let aflags = u16_at(attr, 0x0C);
        let name = if name_len > 0 {
            if name_off + name_len * 2 > alen {
                return Err("attribute name outside attribute".into());
            }
            utf16(&attr[name_off..name_off + name_len * 2])
        } else {
            String::new()
        };

        match atype {
            ATTR_ATTRIBUTE_LIST => out.has_attribute_list = true,

            
            ATTR_FILE_NAME if !non_resident => {
                let clen = u32_at(attr, 0x10) as usize;
                let coff = u16_at(attr, 0x14) as usize;
                if clen < 0x42 || coff + clen > alen {
                    return Err("invalid $FILE_NAME attribute".into());
                }
                let c = &attr[coff..coff + clen];
                let nlen = c[0x40] as usize;
                if 0x42 + nlen * 2 > c.len() {
                    return Err("invalid $FILE_NAME length".into());
                }
                out.file_names.push(utf16(&c[0x42..0x42 + nlen * 2]));
            }

            // The file contents (or the run list that points to them).
            ATTR_DATA => {
                let kind = if !non_resident {
                    let clen = u32_at(attr, 0x10) as usize;
                    let coff = u16_at(attr, 0x14) as usize;
                    if coff + clen > alen {
                        return Err("resident data outside attribute".into());
                    }
                    
                    DataKind::Resident { record_offset: pos + coff, length: clen }
                } else {
                    if alen < 0x40 {
                        return Err("non-resident header too short".into());
                    }
                    let run_off = u16_at(attr, 0x20) as usize;
                    if run_off >= alen {
                        return Err("run list offset outside attribute".into());
                    }
                    DataKind::NonResident {
                       
                        runs: decode_runs(&attr[run_off..])?,
                        allocated_size: u64_at(attr, 0x28),
                        real_size: u64_at(attr, 0x30),
                    }
                };
                out.streams.push(DataStream { name, flags: aflags, kind });
            }
            _ => {}
        }
        // Jump to the next attribute: attributes are stored back to back.
        pos += alen;
    }
    Ok(out)
}


/// Combines the read with `apply_fixups` so that every caller receives a buffer in which the
/// real bytes are back in place.
pub fn read_record(vol: &Volume, offset: u64, record_size: usize) -> Result<Vec<u8>, String> {
    // A zero-filled buffer of exactly one record, filled by the raw read.
    let mut rec = vec![0u8; record_size];
    vol.read_at(offset, &mut rec)?;
    apply_fixups(&mut rec)?;
    Ok(rec)
}


/// Why this extra step: the boot sector only gives the *start* of the MFT. If the MFT has
/// grown in several pieces, record number 5000 might not be at `start + 5000 * 1024`. Record 0
/// always lies at the start and describes the pieces, so we read it first.
pub fn load_mft_runs(vol: &Volume, boot: &BootInfo) -> Result<Vec<Run>, String> {
    let off = boot.mft_cluster * boot.cluster_size as u64;
    let rec = read_record(vol, off, boot.record_size as usize)?;
    let p = parse_record(&rec)?;
    if p.has_attribute_list {
        return Err("$MFT is too fragmented ($ATTRIBUTE_LIST); not supported yet".into());
    }
    let s = p
        .streams
        .into_iter()
        .find(|s| s.name.is_empty())
        .ok_or("$MFT has no data stream")?;
    match s.kind {
        DataKind::NonResident { runs, .. } => Ok(runs),
        _ => Err("$MFT data is unexpectedly resident".into()),
    }
}


pub fn mft_record_offset(
    mft_runs: &[Run],
    cluster_size: u64,
    record_size: u64,
    record_number: u64,
) -> Option<u64> {
    let mut pos = record_number * record_size; // position inside the MFT's data
    for r in mft_runs {
        if r.sparse {
            return None;
        }
        let run_bytes = r.clusters * cluster_size;
       
        if pos < run_bytes {
            return Some(r.lcn * cluster_size + pos);
        }
        pos -= run_bytes;
    }
    None
}


/// Used after NTFS has deleted the file: NTFS only clears the "in use" flag and leaves the
/// old name and resident data inside the record. This function removes those leftovers.
/// The header (including the update sequence array) is kept so the record stays valid and
/// can be reused by NTFS later.
pub fn scrub_free_record(rec: &mut [u8]) -> Result<(), String> {
    let usa_off = u16_at(rec, 4) as usize;
    let usa_cnt = u16_at(rec, 6) as usize;
    let first_attr = u16_at(rec, 0x14) as usize;
    let flags = u16_at(rec, 0x16);
    if flags & 0x01 != 0 {
        return Err("refusing to scrub a record that is in use".into());
    }
    
    if first_attr < 0x30
        || first_attr % 8 != 0
        || first_attr + 8 > rec.len()
        || usa_off + usa_cnt * 2 > first_attr
    {
        return Err("unexpected record layout; not scrubbing".into());
    }
    
    rec[first_attr..].fill(0);
    rec[first_attr..first_attr + 4].copy_from_slice(&ATTR_END.to_le_bytes());
    rec[0x18..0x1C].copy_from_slice(&((first_attr + 8) as u32).to_le_bytes()); // bytes in use
    Ok(())
}


/// A record read with `read_record` has its fixups *removed*. NTFS expects the on-disk form,
/// so after modifying a record this function must run before `Volume::write_at`; otherwise
/// NTFS would consider the record corrupt.
pub fn protect_fixups(rec: &mut [u8]) -> Result<(), String> {
    if rec.len() < 0x30 || &rec[0..4] != b"FILE" {
        return Err("record does not start with 'FILE'".into());
    }
    let usa_off = u16_at(rec, 4) as usize;
    let usa_cnt = u16_at(rec, 6) as usize;
    if usa_cnt < 2 || usa_off + usa_cnt * 2 > rec.len() || (usa_cnt - 1) * 512 > rec.len() {
        return Err("invalid update sequence array".into());
    }
   
    let mut usn = u16_at(rec, usa_off).wrapping_add(1);
    if usn == 0 {
        usn = 1;
    }
    let u = usn.to_le_bytes();
    rec[usa_off] = u[0];
    rec[usa_off + 1] = u[1];
    for i in 1..usa_cnt {
        let end = i * 512 - 2;
        rec[usa_off + i * 2] = rec[end];
        rec[usa_off + i * 2 + 1] = rec[end + 1];
        rec[end] = u[0];
        rec[end + 1] = u[1];
    }
    Ok(())
}
