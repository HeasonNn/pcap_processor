use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use glob::glob;
use log::{info, warn};
use pcap::{Capture, Linktype, Packet, Savefile};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zip::ZipArchive;

use crate::common::{PacketMeta, PacketType, Rule};

// DoHBrw raw PCAP members can be multi-GB. This guard is intentionally far above
// normal dataset sizes and only skips absurd declared sizes that indicate zip-bomb risk.
const MAX_ZIP_MEMBER_UNCOMPRESSED_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024; // 16 TiB

fn decode_l2(data: &[u8], link_type: Linktype) -> Option<(usize, u16)> {
    match link_type {
        Linktype::ETHERNET => {
            if data.len() < 14 {
                return None;
            }
            let et = u16::from_be_bytes([data[12], data[13]]);
            if et == 0x8100 {
                // 802.1Q VLAN: [dst6][src6][8100][tci2][etype2]
                if data.len() < 18 {
                    return None;
                }
                let et2 = u16::from_be_bytes([data[16], data[17]]);
                Some((18, et2))
            } else {
                Some((14, et))
            }
        },
        Linktype(113) => {
            // SLL: protocol at bytes 14..16, payload at 16
            if data.len() < 16 {
                return None;
            }
            let proto = u16::from_be_bytes([data[14], data[15]]);
            Some((16, proto))
        },
        Linktype(12) => {
            // RAW: packet begins with IP header
            if data.is_empty() {
                return None;
            }
            let ver = data[0] >> 4;
            let proto = match ver {
                4 => 0x0800,
                6 => 0x86DD,
                _ => return None,
            };
            Some((0, proto))
        },
        _ => None,
    }
}

/// Wrap a packet payload into a fake Ethernet frame (DLT_EN10MB).
/// - dst MAC: ff:ff:ff:ff:ff:ff (broadcast)
/// - src MAC: 02:00:00:00:00:01 (locally administered)
/// - ethertype/protocol taken from link-layer framing (Ethernet/SLL) or inferred from IP version for RAW
pub fn wrap_to_ethernet(pkt: &Packet, link_type: Linktype) -> Option<(pcap::PacketHeader, Vec<u8>)> {
    let data = pkt.data;
    if data.is_empty() {
        return None;
    }

    if link_type == Linktype::ETHERNET {
        let mut hdr = *pkt.header;
        let out = data.to_vec();
        hdr.caplen = out.len() as u32;
        hdr.len = out.len() as u32;
        return Some((hdr, out));
    }

    let (l3_off, proto) = decode_l2(data, link_type)?;
    let payload = &data[l3_off..];

    // Fake Ethernet header
    let mut eth = Vec::with_capacity(14 + payload.len());
    eth.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst MAC: broadcast
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src MAC: locally administered
    eth.push((proto >> 8) as u8);
    eth.push((proto & 0xff) as u8);
    eth.extend_from_slice(payload);

    let mut hdr = *pkt.header;
    hdr.caplen = eth.len() as u32;
    hdr.len = eth.len() as u32;
    Some((hdr, eth))
}

pub fn parse_packet(packet: &Packet, link_type: Linktype) -> Option<PacketMeta> {
    let data = packet.data;
    let (offset, eth_type) = decode_l2(data, link_type)?;

    let mut packet_code: u16 = 0;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let packet_length: u16;
    let src_ip: IpAddr;
    let dst_ip: IpAddr;
    let next_proto: u8;
    let l4_offset: usize;

    match eth_type {
        0x0800 => {
            if data.len() < offset + 20 {
                return None;
            }

            PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeIpv4);
            let ihl = (data[offset] & 0x0f) as usize * 4;
            if data.len() < offset + ihl {
                return None;
            }

            packet_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            next_proto = data[offset + 9];

            src_ip = IpAddr::V4(Ipv4Addr::new(
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ));
            dst_ip = IpAddr::V4(Ipv4Addr::new(
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            ));

            l4_offset = offset + ihl;
        },
        0x86DD => {
            if data.len() < offset + 40 {
                return None;
            }

            PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeIpv6);
            let payload_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            packet_length = payload_len + 40;

            next_proto = data[offset + 6];

            let mut s_arr = [0u8; 16];
            s_arr.copy_from_slice(&data[offset + 8..offset + 24]);
            let mut d_arr = [0u8; 16];
            d_arr.copy_from_slice(&data[offset + 24..offset + 40]);

            src_ip = IpAddr::V6(Ipv6Addr::from(s_arr));
            dst_ip = IpAddr::V6(Ipv6Addr::from(d_arr));

            l4_offset = offset + 40;
        },
        _ => return None,
    };

    if data.len() > l4_offset {
        match next_proto {
            6 => {
                if data.len() >= l4_offset + 20 {
                    src_port = u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
                    dst_port = u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);

                    let flags = data[l4_offset + 13];
                    if (flags & 0x02) != 0 {
                        PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeTcpSyn);
                    } // SYN
                    if (flags & 0x01) != 0 {
                        PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeTcpFin);
                    } // FIN
                    if (flags & 0x04) != 0 {
                        PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeTcpRst);
                    } // RST
                    if (flags & 0x10) != 0 {
                        PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeTcpAck);
                    } // ACK
                } else {
                    return None;
                }
            },
            17 => {
                if data.len() >= l4_offset + 8 {
                    src_port = u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
                    dst_port = u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);

                    PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeUdp);
                } else {
                    return None;
                }
            },
            1 => {
                PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeIcmp);
            },
            2 => {
                PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeIgmp);
            },
            58 => {
                PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeUnknown);
            },
            _ => {
                PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeUnknown);
            },
        }
    } else {
        PacketMeta::set_pkt_code(&mut packet_code, PacketType::PktTypeUnknown);
    }

    Some(PacketMeta {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: next_proto,
        packet_code,
        ip_len: packet_length,
        ts_ns: (packet.header.ts.tv_sec as i64) * 1_000_000_000 + (packet.header.ts.tv_usec as i64) * 1_000,
    })
}

pub fn compact_pcap(input_path: impl AsRef<Path>, output_path: impl AsRef<Path>) -> Result<()> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();

    let sources = collect_compact_sources(input_path)?;
    if sources.is_empty() {
        anyhow::bail!(
            "No supported pcap/pcapng/zip sources found for input {}",
            input_path.display()
        );
    }

    let output_linktype = Linktype::ETHERNET;
    info!("🔗 Compact output Linktype forced to {:?} (Ethernet)", output_linktype);

    let dead_cap = Capture::dead(output_linktype)?;
    let mut writer = dead_cap.savefile(output_path)?;
    let mut cursor_ns: u64 = 0;
    let gap_ns: u64 = 1_000_000; // 1ms gap between sources

    info!(
        "⚡ Compacting {} sources (sequential time-aligned concat)...",
        sources.len()
    );

    let mut total: u64 = 0;

    for (i, source) in sources.iter().enumerate() {
        process_compact_source(
            source,
            &mut writer,
            &mut cursor_ns,
            gap_ns,
            &mut total,
            i,
            sources.len(),
        )?;
    }

    writer.flush()?;
    info!(
        "✅ Compacted into {} ({} packets, Ethernet, continuous timeline)",
        output_path.display(),
        total
    );
    Ok(())
}

#[derive(Debug)]
enum CompactSource {
    File(PathBuf),
    Zip(PathBuf),
}

#[derive(Debug)]
struct ZipMemberSource {
    index: usize,
    name: String,
    size: u64,
}

fn collect_compact_sources(input_path: &Path) -> Result<Vec<CompactSource>> {
    let mut paths = collect_supported_paths(input_path)?;
    paths.sort_by(|a, b| natord::compare(&a.to_string_lossy(), &b.to_string_lossy()));

    let mut sources = Vec::new();
    for path in paths {
        if is_capture_file(&path) {
            sources.push(CompactSource::File(path));
        } else if is_zip_file(&path) {
            sources.push(CompactSource::Zip(path));
        }
    }

    Ok(sources)
}

fn collect_supported_paths(input_path: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if input_path.is_dir() {
        for entry in std::fs::read_dir(input_path)
            .with_context(|| format!("Failed to read input directory {}", input_path.display()))?
        {
            let path = entry
                .with_context(|| format!("Failed to read directory entry in {}", input_path.display()))?
                .path();
            if is_supported_source_file(&path) {
                paths.push(path);
            }
        }
    } else if input_path.is_file() {
        if is_supported_source_file(input_path) {
            paths.push(input_path.to_path_buf());
        }
    } else {
        let pattern = input_path.to_string_lossy();
        for entry in glob(&pattern).with_context(|| format!("Invalid glob pattern {}", input_path.display()))? {
            let path = entry.with_context(|| format!("Failed to read glob entry for {}", input_path.display()))?;
            if is_supported_source_file(&path) {
                paths.push(path);
            }
        }
    }

    Ok(paths)
}

fn zip_capture_members(archive: &mut ZipArchive<File>, zip_path: &Path) -> Vec<ZipMemberSource> {
    let mut members = Vec::new();

    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(entry) => {
                let member_name = entry.name().to_string();
                if !entry.is_dir() && is_capture_member_name(&member_name) {
                    members.push(ZipMemberSource {
                        index: i,
                        name: member_name,
                        size: entry.size(),
                    });
                }
            },
            Err(err) => {
                warn!(
                    "Skipping unreadable zip entry {} from {}: {}",
                    i,
                    zip_path.display(),
                    err
                );
            },
        };
    }
    members.sort_by(|a, b| natord::compare(&a.name, &b.name));

    members
}

fn is_supported_source_file(path: &Path) -> bool {
    is_capture_file(path) || is_zip_file(path)
}

fn is_capture_file(path: &Path) -> bool {
    matches!(extension_lower(path).as_deref(), Some("pcap" | "pcapng"))
}

fn is_zip_file(path: &Path) -> bool {
    matches!(extension_lower(path).as_deref(), Some("zip"))
}

fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
}

fn is_capture_member_name(member_name: &str) -> bool {
    let lower = member_name.to_ascii_lowercase();
    lower.ends_with(".pcap") || lower.ends_with(".pcapng")
}

fn process_compact_source(
    source: &CompactSource,
    writer: &mut Savefile,
    cursor_ns: &mut u64,
    gap_ns: u64,
    total: &mut u64,
    source_index: usize,
    source_count: usize,
) -> Result<()> {
    match source {
        CompactSource::File(path) => compact_capture_file(
            path,
            &path.display().to_string(),
            writer,
            cursor_ns,
            gap_ns,
            total,
            source_index,
            source_count,
        ),
        CompactSource::Zip(path) => {
            compact_zip_file(path, writer, cursor_ns, gap_ns, total, source_index, source_count)
        },
    }
}

fn compact_zip_file(
    zip_path: &Path,
    writer: &mut Savefile,
    cursor_ns: &mut u64,
    gap_ns: u64,
    total: &mut u64,
    source_index: usize,
    source_count: usize,
) -> Result<()> {
    let file = match File::open(zip_path) {
        Ok(file) => file,
        Err(err) => {
            warn!("Skipping zip {}: failed to open: {}", zip_path.display(), err);
            return Ok(());
        },
    };
    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(err) => {
            warn!("Skipping zip {}: failed to read archive: {}", zip_path.display(), err);
            return Ok(());
        },
    };

    let members = zip_capture_members(&mut archive, zip_path);
    if members.is_empty() {
        warn!("Skipping zip {}: no pcap/pcapng members found", zip_path.display());
        return Ok(());
    }

    let temp_dir = TempDir::new().context("Failed to create temp dir for zip extraction")?;
    for member in members {
        if member.size > MAX_ZIP_MEMBER_UNCOMPRESSED_SIZE {
            warn!(
                "Skipping zip member {}:{}: declared uncompressed size {} exceeds guard {}",
                zip_path.display(),
                member.name,
                member.size,
                MAX_ZIP_MEMBER_UNCOMPRESSED_SIZE
            );
            continue;
        }

        let ext = Path::new(&member.name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("pcap");
        let extracted_path = temp_dir.path().join(format!("member_{}.{}", member.index, ext));
        if let Err(err) = extract_zip_member(&mut archive, zip_path, &member, &extracted_path) {
            warn!(
                "Skipping zip member {}:{}: failed to extract: {}",
                zip_path.display(),
                member.name,
                err
            );
            continue;
        }

        let display_name = format!("{}:{}", zip_path.display(), member.name);
        let compact_result = compact_capture_file(
            &extracted_path,
            &display_name,
            writer,
            cursor_ns,
            gap_ns,
            total,
            source_index,
            source_count,
        );
        if let Err(err) = fs::remove_file(&extracted_path) {
            warn!(
                "Failed to remove temporary zip member file {}: {}",
                extracted_path.display(),
                err
            );
        }
        compact_result?;
    }

    Ok(())
}

fn extract_zip_member(
    archive: &mut ZipArchive<File>,
    zip_path: &Path,
    member: &ZipMemberSource,
    out_path: &Path,
) -> Result<()> {
    let mut entry = archive
        .by_index(member.index)
        .with_context(|| format!("Failed to read zip entry {} from {}", member.index, zip_path.display()))?;

    let mut out =
        File::create(out_path).with_context(|| format!("Failed to create extracted file: {}", out_path.display()))?;
    io::copy(&mut entry, &mut out).with_context(|| format!("Failed to extract zip entry {}", member.name))?;
    Ok(())
}

fn compact_capture_file(
    file_path: &Path,
    display_name: &str,
    writer: &mut Savefile,
    cursor_ns: &mut u64,
    gap_ns: u64,
    total: &mut u64,
    source_index: usize,
    source_count: usize,
) -> Result<()> {
    let mut cap = match Capture::from_file(file_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("Skipping {}: {}", display_name, e);
            return Ok(());
        },
    };
    let lt = cap.get_datalink();

    // Find the first *wrappable* packet to define this source's local time origin.
    let mut file_first_ts_ns: Option<u64> = None;
    let mut file_last_ts_ns: u64 = 0;
    let mut wrote_any = false;

    while let Ok(pkt) = cap.next_packet() {
        if let Some((mut new_hdr, new_data)) = wrap_to_ethernet(&pkt, lt) {
            let ts_ns = (new_hdr.ts.tv_sec as u64) * 1_000_000_000 + (new_hdr.ts.tv_usec as u64) * 1_000;

            if file_first_ts_ns.is_none() {
                file_first_ts_ns = Some(ts_ns);
            }
            let base = file_first_ts_ns.unwrap();
            let rel_ns = ts_ns.saturating_sub(base);
            let new_ts = cursor_ns.saturating_add(rel_ns);

            new_hdr.ts.tv_sec = (new_ts / 1_000_000_000) as _;
            new_hdr.ts.tv_usec = ((new_ts % 1_000_000_000) / 1_000) as _;

            let pkt_ref = Packet {
                header: &new_hdr,
                data: &new_data,
            };
            writer.write(&pkt_ref);

            wrote_any = true;
            *total += 1;
            file_last_ts_ns = ts_ns;

            if *total % 5_000_000 == 0 {
                info!("Processed {} packets...", *total);
            }
        }
    }

    if wrote_any {
        let base = file_first_ts_ns.unwrap_or(file_last_ts_ns);
        let dur = file_last_ts_ns.saturating_sub(base);
        *cursor_ns = cursor_ns.saturating_add(dur.saturating_add(gap_ns));
        info!(
            "[{} / {}] {} -> wrote packets, duration={} ns, next_cursor={} ns",
            source_index + 1,
            source_count,
            display_name,
            dur,
            *cursor_ns
        );
    } else {
        warn!(
            "[{} / {}] {} -> no usable packets",
            source_index + 1,
            source_count,
            display_name
        );
    }

    Ok(())
}

pub fn filter_malicious_pkt(
    raw_pcap_input: &str,
    rules: &Vec<Rule>,
    output_dir: &str,
) -> Result<HashMap<String, String>> {
    let index = build_ip_index(rules)?;
    let mut writers: HashMap<String, Savefile> = HashMap::new();
    let mut generated_paths = HashMap::new();

    let input_path = Path::new(raw_pcap_input);
    let mut files = vec![];
    if input_path.is_dir() {
        for entry in std::fs::read_dir(input_path)? {
            let p = entry?.path();
            if p.extension().and_then(|s| s.to_str()) == Some("pcap") {
                files.push(p);
            }
        }
        files.sort_by(|a, b| natord::compare(&a.to_string_lossy(), &b.to_string_lossy()));
    } else {
        files.push(input_path.to_path_buf());
    }

    if files.is_empty() {
        anyhow::bail!("No pcap files found in {}", raw_pcap_input);
    }

    let dead_cap = Capture::dead(Linktype::ETHERNET)?;
    let benign_path = Path::new(output_dir).join("BENIGN.pcap");
    let benign_path_str = benign_path.to_string_lossy().to_string();
    writers.insert("BENIGN".to_string(), dead_cap.savefile(&benign_path_str)?);
    generated_paths.insert("BENIGN".to_string(), benign_path_str);

    info!("⚡ Filtering {} files...", files.len());
    let mut count = 0u64;

    for file_path in files {
        let mut cap = match Capture::from_file(&file_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Skipping {:?}: {}", file_path, e);
                continue;
            },
        };
        let link_type = cap.get_datalink();

        while let Ok(packet) = cap.next_packet() {
            // Default label for non-IP/unparsable packets
            let mut target_type = "BENIGN";

            if let Some(meta) = parse_packet(&packet, link_type) {
                let ts_f64 = meta.ts_ns as f64 / 1e9;

                if let Some(t) = match_rule(&index, &meta, ts_f64) {
                    target_type = t;
                }
            }

            if let Some((hdr, data)) = wrap_to_ethernet(&packet, link_type) {
                let writer = if let Some(w) = writers.get_mut(target_type) {
                    w
                } else {
                    let out_path = Path::new(output_dir).join(format!("{}.pcap", target_type));
                    let path_str = out_path.to_string_lossy().to_string();
                    generated_paths.insert(target_type.to_string(), path_str.clone());
                    writers.insert(target_type.to_string(), dead_cap.savefile(path_str)?);
                    writers.get_mut(target_type).unwrap()
                };

                let pkt_ref = Packet {
                    header: &hdr,
                    data: &data,
                };
                writer.write(&pkt_ref);
            }

            count += 1;
            if count % 5_000_000 == 0 {
                info!("Processed {} packets...", count);
            }
        }
    }

    for (_, w) in writers.iter_mut() {
        w.flush()?;
    }
    Ok(generated_paths)
}

fn build_ip_index(rules: &Vec<Rule>) -> Result<HashMap<IpAddr, Vec<(f64, f64, String, String)>>> {
    let mut index = HashMap::new();
    for r in rules {
        let s = parse_time(&r.start_time)?;
        let e = parse_time(&r.end_time)?;
        let direction = r
            .direction
            .clone()
            .unwrap_or_else(|| "either".to_string())
            .to_lowercase();
        if !matches!(direction.as_str(), "src" | "dst" | "either") {
            anyhow::bail!("Invalid rule direction '{}': expected src, dst, or either", direction);
        }
        for ip_str in &r.attackers {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                index
                    .entry(ip)
                    .or_insert_with(Vec::new)
                    .push((s, e, r.attack_type.clone(), direction.clone()));
            } else {
                warn!("Invalid IP: {}", ip_str);
            }
        }
    }
    Ok(index)
}

fn match_rule<'a>(
    index: &'a HashMap<IpAddr, Vec<(f64, f64, String, String)>>,
    meta: &PacketMeta,
    ts_f64: f64,
) -> Option<&'a str> {
    if let Some(rules) = index.get(&meta.src_ip) {
        if let Some((_, _, t, _)) = rules
            .iter()
            .find(|(s, e, _, direction)| ts_f64 >= *s && ts_f64 <= *e && (direction == "src" || direction == "either"))
        {
            return Some(t.as_str());
        }
    }

    if let Some(rules) = index.get(&meta.dst_ip) {
        if let Some((_, _, t, _)) = rules
            .iter()
            .find(|(s, e, _, direction)| ts_f64 >= *s && ts_f64 <= *e && (direction == "dst" || direction == "either"))
        {
            return Some(t.as_str());
        }
    }

    None
}

fn parse_time(s: &str) -> Result<f64> {
    let fmts = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"];
    for f in fmts {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, f) {
            return Ok(dt.and_utc().timestamp() as f64);
        }
    }
    anyhow::bail!("Invalid time format: {}", s)
}

#[cfg(test)]
mod tests {
    use super::compact_pcap;
    use pcap::{Capture, Linktype, Packet, PacketHeader};
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn ethernet_ipv4_tcp_packet(src_last_octet: u8) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.extend_from_slice(&[
            0x45,
            0x00,
            0x00,
            0x28,
            0x00,
            0x00,
            0x40,
            0x00,
            0x40,
            0x06,
            0x00,
            0x00,
            10,
            0,
            0,
            src_last_octet,
            10,
            0,
            0,
            2,
        ]);
        pkt.extend_from_slice(&[
            0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        pkt
    }

    fn write_test_pcap(path: &Path, src_last_octet: u8, tv_sec: i64, tv_usec: i64) {
        let dead = Capture::dead(Linktype::ETHERNET).unwrap();
        let mut writer = dead.savefile(path).unwrap();
        let data = ethernet_ipv4_tcp_packet(src_last_octet);
        let mut header = PacketHeader {
            ts: unsafe { std::mem::zeroed() },
            caplen: data.len() as u32,
            len: data.len() as u32,
        };
        header.ts.tv_sec = tv_sec;
        header.ts.tv_usec = tv_usec;
        let packet = Packet::new(&header, &data);
        writer.write(&packet);
        writer.flush().unwrap();
    }

    fn output_packet_summary(path: &Path) -> (Linktype, Vec<(i64, i64, u8)>) {
        let mut cap = Capture::from_file(path).unwrap();
        let linktype = cap.get_datalink();
        let mut packets = Vec::new();
        while let Ok(packet) = cap.next_packet() {
            packets.push((packet.header.ts.tv_sec, packet.header.ts.tv_usec, packet.data[29]));
        }
        (linktype, packets)
    }

    #[test]
    fn compact_pcap_accepts_glob_pattern_and_naturally_sorts_sources() {
        let temp = tempdir().unwrap();
        let input_dir = temp.path().join("inputs");
        fs::create_dir(&input_dir).unwrap();
        write_test_pcap(&input_dir.join("source10.pcap"), 10, 10, 0);
        write_test_pcap(&input_dir.join("source2.pcap"), 2, 20, 0);

        let output = temp.path().join("out.pcap");
        let pattern = input_dir.join("*.pcap").to_string_lossy().to_string();
        compact_pcap(&pattern, &output).unwrap();

        let (linktype, packets) = output_packet_summary(&output);
        assert_eq!(linktype, Linktype::ETHERNET);
        assert_eq!(packets, vec![(0, 0, 2), (0, 1000, 10)]);
    }

    #[test]
    fn compact_pcap_accepts_glob_with_zip_pcap_member() {
        let temp = tempdir().unwrap();
        let member = temp.path().join("member.pcap");
        write_test_pcap(&member, 7, 30, 500);
        let member_bytes = fs::read(&member).unwrap();

        let zip_path = temp.path().join("captures.zip");
        {
            let zip_file = fs::File::create(&zip_path).unwrap();
            let mut zip = ZipWriter::new(zip_file);
            let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("ignored.txt", options).unwrap();
            zip.write_all(b"ignored").unwrap();
            zip.start_file("nested/member.pcap", options).unwrap();
            zip.write_all(&member_bytes).unwrap();
            zip.finish().unwrap();
        }

        let output = temp.path().join("out.pcap");
        let pattern = temp.path().join("*.zip").to_string_lossy().to_string();
        compact_pcap(&pattern, &output).unwrap();

        let (linktype, packets) = output_packet_summary(&output);
        assert_eq!(linktype, Linktype::ETHERNET);
        assert_eq!(packets, vec![(0, 0, 7)]);
    }

    #[test]
    fn compact_pcap_skips_corrupt_zip_matched_by_glob() {
        let temp = tempdir().unwrap();
        let valid = temp.path().join("valid.pcap");
        write_test_pcap(&valid, 3, 10, 0);
        fs::write(temp.path().join("bad.zip"), b"not a zip archive").unwrap();

        let output = temp.path().join("out.pcap");
        let pattern = temp.path().join("*").to_string_lossy().to_string();
        compact_pcap(&pattern, &output).unwrap();

        let (linktype, packets) = output_packet_summary(&output);
        assert_eq!(linktype, Linktype::ETHERNET);
        assert_eq!(packets, vec![(0, 0, 3)]);
    }

    #[test]
    fn compact_pcap_processes_multiple_zip_members_in_natural_name_order() {
        let temp = tempdir().unwrap();
        let member10 = temp.path().join("member10.pcap");
        let member2 = temp.path().join("member2.pcap");
        write_test_pcap(&member10, 10, 10, 0);
        write_test_pcap(&member2, 2, 20, 0);

        let zip_path = temp.path().join("captures.zip");
        {
            let zip_file = fs::File::create(&zip_path).unwrap();
            let mut zip = ZipWriter::new(zip_file);
            let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("z/member10.pcap", options).unwrap();
            zip.write_all(&fs::read(&member10).unwrap()).unwrap();
            zip.start_file("z/member2.pcap", options).unwrap();
            zip.write_all(&fs::read(&member2).unwrap()).unwrap();
            zip.finish().unwrap();
        }

        let output = temp.path().join("out.pcap");
        compact_pcap(&zip_path, &output).unwrap();

        let (linktype, packets) = output_packet_summary(&output);
        assert_eq!(linktype, Linktype::ETHERNET);
        assert_eq!(packets, vec![(0, 0, 2), (0, 1000, 10)]);
    }
}
