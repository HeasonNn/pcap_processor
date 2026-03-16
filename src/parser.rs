use anyhow::Result;
use chrono::NaiveDateTime;
use log::{info, warn};
use pcap::{Capture, Linktype, Packet, Savefile};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::common::{PacketMeta, PacketType, Rule};

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
        packet_code,
        ip_len: packet_length,
        ts_ns: (packet.header.ts.tv_sec as i64) * 1_000_000_000 + (packet.header.ts.tv_usec as i64) * 1_000,
    })
}

pub fn compact_pcap(input_path: impl AsRef<Path>, output_path: impl AsRef<Path>) -> Result<()> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();

    let mut files = vec![];
    for entry in std::fs::read_dir(input_path)? {
        let p = entry?.path();
        if p.extension().and_then(|s| s.to_str()) == Some("pcap") {
            files.push(p);
        }
    }
    files.sort_by(|a, b| natord::compare(&a.to_string_lossy(), &b.to_string_lossy()));

    if files.is_empty() {
        anyhow::bail!("No pcap files found in {}", input_path.display());
    }

    let output_linktype = Linktype::ETHERNET;
    info!("🔗 Compact output Linktype forced to {:?} (Ethernet)", output_linktype);

    let dead_cap = Capture::dead(output_linktype)?;
    let mut writer = dead_cap.savefile(output_path)?;
    let mut cursor_ns: u64 = 0;
    let gap_ns: u64 = 1_000_000; // 1ms gap between files

    info!(
        "⚡ Compacting {} files (sequential time-aligned concat)...",
        files.len()
    );

    let mut total: u64 = 0;

    for (i, file_path) in files.iter().enumerate() {
        let mut cap = match Capture::from_file(file_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Skipping {:?}: {}", file_path, e);
                continue;
            },
        };
        let lt = cap.get_datalink();

        // Find the first *wrappable* packet to define this file's local time origin.
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
                total += 1;
                file_last_ts_ns = ts_ns;

                if total % 5_000_000 == 0 {
                    info!("Processed {} packets...", total);
                }
            } else {
                continue;
            }
        }

        if wrote_any {
            let base = file_first_ts_ns.unwrap_or(file_last_ts_ns);
            let dur = file_last_ts_ns.saturating_sub(base);
            cursor_ns = cursor_ns.saturating_add(dur.saturating_add(gap_ns));
            info!(
                "[{} / {}] {} -> wrote packets, duration={} ns, next_cursor={} ns",
                i + 1,
                files.len(),
                file_path.display(),
                dur,
                cursor_ns
            );
        } else {
            warn!(
                "[{} / {}] {} -> no usable packets",
                i + 1,
                files.len(),
                file_path.display()
            );
        }
    }

    writer.flush()?;
    info!(
        "✅ Compacted into {} ({} packets, Ethernet, continuous timeline)",
        output_path.display(),
        total
    );
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

                if let Some(rules) = index.get(&meta.src_ip) {
                    if let Some((_, _, t)) = rules.iter().find(|(s, e, _)| ts_f64 >= *s && ts_f64 <= *e) {
                        target_type = t;
                    }
                }
                if target_type == "BENIGN" {
                    if let Some(rules) = index.get(&meta.dst_ip) {
                        if let Some((_, _, t)) = rules.iter().find(|(s, e, _)| ts_f64 >= *s && ts_f64 <= *e) {
                            target_type = t;
                        }
                    }
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

fn build_ip_index(rules: &Vec<Rule>) -> Result<HashMap<IpAddr, Vec<(f64, f64, String)>>> {
    let mut index = HashMap::new();
    for r in rules {
        let s = parse_time(&r.start_time)?;
        let e = parse_time(&r.end_time)?;
        for ip_str in &r.attackers {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                index
                    .entry(ip)
                    .or_insert_with(Vec::new)
                    .push((s, e, r.attack_type.clone()));
            } else {
                warn!("Invalid IP: {}", ip_str);
            }
        }
    }
    Ok(index)
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
