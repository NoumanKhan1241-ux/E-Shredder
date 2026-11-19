use crate::win::Volume;

pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

// ---------- little-endian helpers ----------
fn u16_at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn u32_at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn u64_at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
fn utf16(b: &[u8]) -> String {
    let v: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&v)
}

// ---------- boot sector ----------
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
    // Positive = clusters per record; negative = record size is 2^(-n) bytes.
    let raw = s[0x40] as i8;
    let record_size = if raw > 0 { raw as u32 * cluster_size } else { 1u32 << (-(raw as i32)) };
    Ok(BootInfo { bytes_per_sector, cluster_size, record_size, mft_cluster })
}

// ---------- data runs ----------
#[derive(Debug, Clone)]
pub struct Run {
    pub lcn: u64,      // start cluster on the volume (meaningless if sparse)
    pub clusters: u64, // length in clusters
    pub sparse: bool,  // hole: no clusters are actually allocated
}

/// Decode an NTFS run list. Each run: header byte (high nibble = size of the offset
/// field, low nibble = size of the length field), then length, then a SIGNED offset
/// that is relative to the previous run's start cluster. A 0x00 header ends the list.
pub fn decode_runs(data: &[u8]) -> Result<Vec<Run>, String> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut lcn: i64 = 0;

    while pos < data.len() {
        let header = data[pos];
        if header == 0 {
            break;
        }
        pos += 1;
        let len_size = (header & 0x0F) as usize;
        let off_size = (header >> 4) as usize;
        if len_size == 0 || len_size > 8 || off_size > 8 || pos + len_size + off_size > data.len() {
            return Err(format!("corrupt run list (header 0x{header:02X})"));
        }

        let mut clusters: u64 = 0;
        for i in 0..len_size {
            clusters |= (data[pos + i] as u64) << (8 * i);
        }
        pos += len_size;

        if off_size == 0 {
            runs.push(Run { lcn: 0, clusters, sparse: true });
            continue;
        }

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

// ---------- MFT record ----------
/// An MFT record stores, at the end of every 512-byte sector, a copy of a "sequence
/// number" instead of the real last two bytes. The real bytes live in the update
/// sequence array. We must restore them before parsing anything.
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
        if rec[end..end + 2] != usn {
            return Err(format!("fixup mismatch in sector {i} (torn or corrupt record)"));
        }
        rec[end] = rec[usa_off + i * 2];
        rec[end + 1] = rec[usa_off + i * 2 + 1];
    }
    Ok(())
}

pub enum DataKind {
    /// Data stored inside the MFT record itself (small files).
    Resident { record_offset: usize, length: usize },
    /// Data stored in clusters elsewhere on the volume.
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

/// Parse a record whose fixups were already applied.
pub fn parse_record(rec: &[u8]) -> Result<ParsedRecord, String> {
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
        pos += alen;
    }
    Ok(out)
}

// ---------- reading records from the volume ----------
pub fn read_record(vol: &Volume, offset: u64, record_size: usize) -> Result<Vec<u8>, String> {
    let mut rec = vec![0u8; record_size];
    vol.read_at(offset, &mut rec)?;
    apply_fixups(&mut rec)?;
    Ok(rec)
}

/// The MFT is itself a file (record 0, "$MFT") and can be fragmented, so we read
/// ITS data runs and use them to find any record.
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

/// Byte offset on the volume of MFT record `record_number`.
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