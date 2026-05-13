use anyhow::{Context, Result};
use glob::glob;
use log::{info, warn};
use pcap::{Capture, Linktype, Offline, Packet, PacketHeader};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use crate::common::FlowKey;
use crate::export::DatasetWriter;

pub trait MergeStrategy {
    fn execute(&self, output_prefix_str: &str) -> Result<usize>;
}

pub struct HashSamplingStrategy {
    attack_str: String,
    benign_str: String,
    sampling_rate: f64,
    write_mixed_pcap: bool,
}

impl HashSamplingStrategy {
    pub fn new(attack_str: &str, benign_str: &str, sampling_rate: f64, write_mixed_pcap: bool) -> Self {
        Self {
            attack_str: attack_str.to_string(),
            benign_str: benign_str.to_string(),
            sampling_rate,
            write_mixed_pcap,
        }
    }
}

impl MergeStrategy for HashSamplingStrategy {
    fn execute(&self, output_prefix_str: &str) -> Result<usize> {
        info!(
            "🚀 Running Merge: Hash-based Sampling Mode (Rate: {:.2})",
            self.sampling_rate
        );

        let mut atk_stream = PcapStreamer::new(&self.attack_str, false)?;
        let mut ben_stream = PcapStreamer::new(&self.benign_str, true)?;
        ben_stream.scan_duration()?;

        let out_linktype = Linktype::ETHERNET;
        atk_stream.open_next()?;
        ben_stream.open_next()?;

        let mut pcap_writer = if self.write_mixed_pcap {
            let cap_dead = Capture::dead(out_linktype)?;
            Some(cap_dead.savefile(format!("{}_mixed.pcap", output_prefix_str))?)
        } else {
            None
        };
        let mut ds_writer = DatasetWriter::new(output_prefix_str)?;

        let (mut curr_atk, mut curr_atk_lt) = match atk_stream.next_packet_with_linktype() {
            Some((p, lt)) => (p, lt),
            None => {
                warn!("⚠️ Attack pcap is empty.");
                return Ok(0);
            },
        };

        let atk_start_ns = curr_atk.timestamp_ns();
        let cycle_base_ns = atk_start_ns.saturating_sub(ben_stream.duration_ns / 10);
        let mut curr_ben = ben_stream.next_packet_with_linktype();

        let mut rng = rand::thread_rng();
        let mut count = 0;
        let mut ds_written = 0usize;
        let mut ds_skipped = 0usize;

        let sampling_rate = self.sampling_rate.clamp(0.0, 1.0);
        let hash_threshold = (u64::MAX as f64 * sampling_rate) as u64;

        loop {
            let ben_ts = match &curr_ben {
                Some((b, _lt)) => {
                    cycle_base_ns
                        + b.timestamp_ns().saturating_sub(ben_stream.base_start_ns)
                        + ben_stream.loop_offset_ns
                },
                None => u64::MAX,
            };
            let atk_ts = curr_atk.timestamp_ns();

            if atk_ts <= ben_ts {
                curr_atk.set_timestamp(atk_ts);
                write_pcap_and_dataset(
                    pcap_writer.as_mut(),
                    &mut ds_writer,
                    out_linktype,
                    &curr_atk,
                    curr_atk_lt,
                    true,
                    &mut ds_written,
                    &mut ds_skipped,
                )?;
                count += 1;
                match atk_stream.next_packet_with_linktype() {
                    Some((p, lt)) => {
                        curr_atk = p;
                        curr_atk_lt = lt;
                    },
                    None => break,
                }
            } else if let Some((mut b, b_lt)) = curr_ben {
                let should_keep = if sampling_rate >= 1.0 {
                    true
                } else if let Some(key) = parse_packet_to_key(&b, b_lt) {
                    key.canonical().get_hash() < hash_threshold
                } else {
                    rng.gen_bool(sampling_rate)
                };

                curr_ben = ben_stream.next_packet_with_linktype();

                if !should_keep {
                    continue;
                }

                b.set_timestamp(ben_ts);
                write_pcap_and_dataset(
                    pcap_writer.as_mut(),
                    &mut ds_writer,
                    out_linktype,
                    &b,
                    b_lt,
                    false,
                    &mut ds_written,
                    &mut ds_skipped,
                )?;
                count += 1;
            } else {
                break;
            }
        }
        if let Some(writer) = pcap_writer.as_mut() {
            writer.flush()?;
        }
        ds_writer.flush()?;
        if ds_written == 0 {
            warn!("⚠️ Dataset export produced 0 rows (skipped {}).", ds_skipped);
        } else {
            info!("   ✅ Dataset rows written: {} (skipped: {})", ds_written, ds_skipped);
        }
        Ok(count)
    }
}

pub struct BudgetControlStrategy {
    attack_str: String,
    benign_str: String,
    total_pkts: u64,
    attack_ratio: f64,
    time_bins: usize,
    bidirectional: bool,
    write_mixed_pcap: bool,
}

impl BudgetControlStrategy {
    pub fn new(
        attack_str: &str,
        benign_str: &str,
        total_pkts: u64,
        attack_ratio: f64,
        time_bins: usize,
        bidirectional: bool,
        write_mixed_pcap: bool,
    ) -> Self {
        Self {
            attack_str: attack_str.to_string(),
            benign_str: benign_str.to_string(),
            total_pkts,
            attack_ratio,
            time_bins,
            bidirectional,
            write_mixed_pcap,
        }
    }
}

impl MergeStrategy for BudgetControlStrategy {
    fn execute(&self, output_prefix_str: &str) -> Result<usize> {
        info!(
            "🚀 Running Merge: Budget Control Mode (Total: {}, Attack Ratio: {:.2})",
            self.total_pkts, self.attack_ratio
        );

        let r_atk = self.attack_ratio.clamp(0.0, 1.0);
        let b_atk = ((self.total_pkts as f64) * r_atk).floor() as u64;
        let b_ben = self.total_pkts.saturating_sub(b_atk);

        info!("   -> Scanning flow stats...");
        let (atk_stats, atk_min, atk_max) = scan_flow_stats(&self.attack_str, self.bidirectional)?;
        let (ben_stats, ben_min, ben_max) = scan_flow_stats(&self.benign_str, self.bidirectional)?;

        let min_ts = atk_min.min(ben_min);
        let max_ts = atk_max.max(ben_max);

        info!("   -> Selecting flows...");
        let selected_atk = select_flows_by_budget(&atk_stats, min_ts, max_ts, b_atk, self.time_bins, true);
        let selected_ben = select_flows_by_budget(&ben_stats, min_ts, max_ts, b_ben, self.time_bins, false);

        let mut atk_stream = PcapStreamer::new(&self.attack_str, false)?;
        let mut ben_stream = PcapStreamer::new(&self.benign_str, true)?;
        ben_stream.scan_duration()?;

        let out_linktype = Linktype::ETHERNET;
        atk_stream.open_next()?;
        ben_stream.open_next()?;

        let mut pcap_writer = if self.write_mixed_pcap {
            let cap_dead = Capture::dead(out_linktype)?;
            Some(cap_dead.savefile(format!("{}_mixed.pcap", output_prefix_str))?)
        } else {
            None
        };
        let mut ds_writer = DatasetWriter::new(output_prefix_str)?;
        let mut ds_written = 0usize;
        let mut ds_skipped = 0usize;

        let mut atk_budget_left = b_atk;
        let mut ben_budget_left = b_ben;

        let (mut curr_atk, mut curr_atk_lt) =
            match next_selected_packet(&mut atk_stream, &selected_atk, self.bidirectional, &mut atk_budget_left) {
                Some((p, lt)) => (p, lt),
                None => {
                    warn!("⚠️ Attack budget selection resulted in empty stream.");
                    return Ok(0);
                },
            };
        let atk_start_ns = curr_atk.timestamp_ns();
        let cycle_base_ns = atk_start_ns.saturating_sub(ben_stream.duration_ns / 10);
        let mut curr_ben =
            next_selected_packet(&mut ben_stream, &selected_ben, self.bidirectional, &mut ben_budget_left);

        let mut count = 0;
        loop {
            let ben_ts = match &curr_ben {
                Some((b, _lt)) => {
                    cycle_base_ns
                        + b.timestamp_ns().saturating_sub(ben_stream.base_start_ns)
                        + ben_stream.loop_offset_ns
                },
                None => u64::MAX,
            };
            let atk_ts = curr_atk.timestamp_ns();

            if atk_ts <= ben_ts {
                curr_atk.set_timestamp(atk_ts);
                write_pcap_and_dataset(
                    pcap_writer.as_mut(),
                    &mut ds_writer,
                    out_linktype,
                    &curr_atk,
                    curr_atk_lt,
                    true,
                    &mut ds_written,
                    &mut ds_skipped,
                )?;
                count += 1;
                match next_selected_packet(&mut atk_stream, &selected_atk, self.bidirectional, &mut atk_budget_left) {
                    Some((p, lt)) => {
                        curr_atk = p;
                        curr_atk_lt = lt;
                    },
                    None => break,
                }
            } else if let Some((mut b, b_lt)) = curr_ben {
                b.set_timestamp(ben_ts);
                write_pcap_and_dataset(
                    pcap_writer.as_mut(),
                    &mut ds_writer,
                    out_linktype,
                    &b,
                    b_lt,
                    false,
                    &mut ds_written,
                    &mut ds_skipped,
                )?;
                count += 1;
                curr_ben =
                    next_selected_packet(&mut ben_stream, &selected_ben, self.bidirectional, &mut ben_budget_left);
            } else {
                break;
            }
        }

        if let Some(writer) = pcap_writer.as_mut() {
            writer.flush()?;
        }
        ds_writer.flush()?;
        if ds_written == 0 {
            warn!("⚠️ Dataset export produced 0 rows (skipped {}).", ds_skipped);
        } else {
            info!("   ✅ Dataset rows written: {} (skipped: {})", ds_written, ds_skipped);
        }
        Ok(count)
    }
}

pub fn export_benign_dataset(benign_str: &str, output_prefix_str: &str, write_pcap: bool) -> Result<usize> {
    info!(
        "🚀 Exporting standalone benign dataset: {} -> {}",
        benign_str, output_prefix_str
    );

    let mut ben_stream = PcapStreamer::new(benign_str, false)?;
    ben_stream.open_next()?;

    let out_linktype = Linktype::ETHERNET;
    let mut pcap_writer = if write_pcap {
        let cap_dead = Capture::dead(out_linktype)?;
        Some(cap_dead.savefile(format!("{}.pcap", output_prefix_str))?)
    } else {
        None
    };
    let mut ds_writer = DatasetWriter::new_data_only(output_prefix_str)?;
    let mut count = 0usize;
    let mut ds_written = 0usize;
    let mut ds_skipped = 0usize;

    while let Some((packet, link_type)) = ben_stream.next_packet_with_linktype() {
        write_pcap_and_dataset(
            pcap_writer.as_mut(),
            &mut ds_writer,
            out_linktype,
            &packet,
            link_type,
            false,
            &mut ds_written,
            &mut ds_skipped,
        )?;
        count += 1;
    }

    if let Some(writer) = pcap_writer.as_mut() {
        writer.flush()?;
    }
    ds_writer.flush()?;
    info!(
        "   ✅ Benign dataset rows written: {} (skipped: {})",
        ds_written, ds_skipped
    );
    Ok(count)
}

pub fn merge_pcap(
    attack_str: &str,
    benign_str: &str,
    output_prefix_str: &str,
    sampling_rate: f64,
    write_mixed_pcap: bool,
) -> Result<usize> {
    let controlled_total_pkts = env::var("PCAP_MERGE_TOTAL_PKTS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let controlled_attack_ratio = env::var("PCAP_MERGE_ATTACK_RATIO")
        .ok()
        .and_then(|v| v.parse::<f64>().ok());

    let strategy: Box<dyn MergeStrategy> =
        if let (Some(total), Some(ratio)) = (controlled_total_pkts, controlled_attack_ratio) {
            let bins = env::var("PCAP_MERGE_TIME_BINS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(30);
            let bidir = env::var("PCAP_MERGE_BIDIR_FLOW")
                .ok()
                .and_then(|v| v.to_lowercase().parse::<bool>().ok())
                .unwrap_or(false);

            Box::new(BudgetControlStrategy::new(
                attack_str,
                benign_str,
                total,
                ratio,
                bins,
                bidir,
                write_mixed_pcap,
            ))
        } else {
            Box::new(HashSamplingStrategy::new(
                attack_str,
                benign_str,
                sampling_rate,
                write_mixed_pcap,
            ))
        };

    strategy.execute(output_prefix_str)
}

#[derive(Clone)]
struct OwnedPacket {
    header: PacketHeader,
    data: Vec<u8>,
}

impl OwnedPacket {
    fn from_pcap(packet: &Packet) -> Self {
        Self {
            header: *packet.header,
            data: packet.data.to_vec(),
        }
    }
    fn as_pcap_packet(&self) -> Packet<'_> {
        Packet {
            header: &self.header,
            data: &self.data,
        }
    }
    fn timestamp_ns(&self) -> u64 {
        (self.header.ts.tv_sec as u64) * 1_000_000_000 + (self.header.ts.tv_usec as u64) * 1_000
    }
    fn set_timestamp(&mut self, ts_ns: u64) {
        self.header.ts.tv_sec = (ts_ns / 1_000_000_000) as _;
        self.header.ts.tv_usec = ((ts_ns % 1_000_000_000) / 1_000) as _;
    }
}

fn wrap_owned_to_ethernet(op: &OwnedPacket, link_type: Linktype) -> Option<OwnedPacket> {
    let pkt_ref = op.as_pcap_packet();
    let (hdr, data) = crate::parser::wrap_to_ethernet(&pkt_ref, link_type)?;
    Some(OwnedPacket { header: hdr, data })
}

fn write_pcap_and_dataset(
    pcap_writer: Option<&mut pcap::Savefile>,
    ds_writer: &mut DatasetWriter,
    out_linktype: Linktype,
    op: &OwnedPacket,
    op_lt: Linktype,
    is_pos: bool,
    ds_written: &mut usize,
    ds_skipped: &mut usize,
) -> Result<()> {
    if let Some(wp) = wrap_owned_to_ethernet(op, op_lt) {
        let pkt_ref = wp.as_pcap_packet();
        if let Some(writer) = pcap_writer {
            writer.write(&pkt_ref);
        }
        if let Some(meta) = crate::parser::parse_packet(&pkt_ref, out_linktype) {
            ds_writer.write_from_meta(&meta, is_pos)?;
            *ds_written += 1;
        } else {
            *ds_skipped += 1;
        }
    } else {
        *ds_skipped += 1;
    }
    Ok(())
}

struct PcapStreamer {
    files: Vec<PathBuf>,
    current_file_idx: usize,
    capture: Option<Capture<Offline>>,
    is_looping: bool,
    duration_ns: u64,
    loop_offset_ns: u64,
    base_start_ns: u64,
    current_linktype: Option<Linktype>,
}

impl PcapStreamer {
    fn new(pattern: &str, is_looping: bool) -> Result<Self> {
        let mut files = Vec::new();
        for entry in glob(pattern).context("Invalid glob pattern")? {
            files.push(entry?);
        }
        if files.is_empty() {
            let path = PathBuf::from(pattern);
            if path.exists() {
                files.push(path);
            } else {
                anyhow::bail!("No pcap files: {}", pattern);
            }
        }
        files.sort();
        Ok(Self {
            files,
            current_file_idx: 0,
            capture: None,
            is_looping,
            duration_ns: 0,
            loop_offset_ns: 0,
            base_start_ns: 0,
            current_linktype: None,
        })
    }

    fn scan_duration(&mut self) -> Result<()> {
        if self.files.is_empty() {
            return Ok(());
        }
        let mut cap = Capture::from_file(&self.files[0])?;
        let first_pkt = cap.next_packet().context("Empty pcap")?;
        self.base_start_ns =
            (first_pkt.header.ts.tv_sec as u64) * 1_000_000_000 + (first_pkt.header.ts.tv_usec as u64) * 1_000;
        let last_file = self.files.last().unwrap();
        let mut cap = Capture::from_file(last_file)?;
        let mut last_ts = self.base_start_ns;
        while let Ok(pkt) = cap.next_packet() {
            last_ts = (pkt.header.ts.tv_sec as u64) * 1_000_000_000 + (pkt.header.ts.tv_usec as u64) * 1_000;
        }
        self.duration_ns = last_ts.saturating_sub(self.base_start_ns);
        Ok(())
    }

    fn open_next(&mut self) -> Result<bool> {
        if self.current_file_idx >= self.files.len() {
            if self.is_looping {
                self.current_file_idx = 0;
                self.loop_offset_ns += self.duration_ns + 1_000_000;
            } else {
                return Ok(false);
            }
        }
        let cap = Capture::from_file(&self.files[self.current_file_idx])?;
        self.current_linktype = Some(cap.get_datalink());
        self.capture = Some(cap);
        self.current_file_idx += 1;
        Ok(true)
    }

    fn next_packet_with_linktype(&mut self) -> Option<(OwnedPacket, Linktype)> {
        loop {
            if self.capture.is_none() {
                if !self.open_next().unwrap_or(false) {
                    return None;
                }
            }
            let lt = self.current_linktype.unwrap_or(Linktype::ETHERNET);
            match self.capture.as_mut().unwrap().next_packet() {
                Ok(pkt) => return Some((OwnedPacket::from_pcap(&pkt), lt)),
                Err(pcap::Error::NoMorePackets) => {
                    self.capture = None;
                    self.current_linktype = None;
                    continue;
                },
                _ => return None,
            }
        }
    }
}

fn parse_packet_to_key(pkt: &OwnedPacket, link_type: Linktype) -> Option<FlowKey> {
    let data = &pkt.data;
    if data.is_empty() {
        return None;
    }

    // Determine L3 offset and ethertype/proto
    let (l3_offset, ethertype) = match link_type {
        Linktype::ETHERNET => {
            if data.len() < 14 {
                return None;
            }
            let et = u16::from_be_bytes([data[12], data[13]]);
            if et == 0x8100 {
                if data.len() < 18 {
                    return None;
                }
                let et2 = u16::from_be_bytes([data[16], data[17]]);
                (18usize, et2)
            } else {
                (14usize, et)
            }
        },
        Linktype(113) => {
            if data.len() < 16 {
                return None;
            }
            let et = u16::from_be_bytes([data[14], data[15]]);
            (16usize, et)
        },
        Linktype(12) => {
            let ver = data[0] >> 4;
            let et = match ver {
                4 => 0x0800,
                6 => 0x86DD,
                _ => return None,
            };
            (0usize, et)
        },
        _ => return None,
    };

    match ethertype {
        0x0800 => {
            // IPv4
            if data.len() < l3_offset + 20 {
                return None;
            }
            let ip = &data[l3_offset..];
            if (ip[0] >> 4) != 4 {
                return None;
            }
            let ihl = (ip[0] & 0x0F) as usize * 4;
            if ip.len() < ihl + 4 {
                return None;
            }
            let proto = ip[9];
            let src_ip = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));

            let mut sport = 0u16;
            let mut dport = 0u16;
            if proto == 6 || proto == 17 {
                let l4 = &ip[ihl..];
                if l4.len() >= 4 {
                    sport = u16::from_be_bytes([l4[0], l4[1]]);
                    dport = u16::from_be_bytes([l4[2], l4[3]]);
                }
            }
            Some(FlowKey::new(src_ip, dst_ip, sport, dport, proto))
        },
        0x86DD => {
            // IPv6
            if data.len() < l3_offset + 40 {
                return None;
            }
            let ip = &data[l3_offset..];
            if (ip[0] >> 4) != 6 {
                return None;
            }
            let proto = ip[6];

            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&ip[8..24]);
            dst_bytes.copy_from_slice(&ip[24..40]);
            let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

            let mut sport = 0u16;
            let mut dport = 0u16;
            if proto == 6 || proto == 17 {
                let l4 = &ip[40..];
                if l4.len() >= 4 {
                    sport = u16::from_be_bytes([l4[0], l4[1]]);
                    dport = u16::from_be_bytes([l4[2], l4[3]]);
                }
            }
            Some(FlowKey::new(src_ip, dst_ip, sport, dport, proto))
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::merge_pcap;
    use pcap::{Capture, Linktype, Packet, PacketHeader};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_prefix(name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("pcap_processor_{name}_{nanos}"))
    }

    fn ethernet_ipv4_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        pkt.extend_from_slice(&[
            0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        pkt
    }

    fn write_test_pcap(path: &PathBuf) {
        let dead = Capture::dead(Linktype::ETHERNET).unwrap();
        let mut writer = dead.savefile(path).unwrap();
        let data = ethernet_ipv4_tcp_packet();
        let header = PacketHeader {
            ts: unsafe { std::mem::zeroed() },
            caplen: data.len() as u32,
            len: data.len() as u32,
        };
        let packet = Packet::new(&header, &data);
        writer.write(&packet);
        writer.flush().unwrap();
    }

    #[test]
    fn merge_can_skip_mixed_pcap_but_keep_dataset_files() {
        let root = unique_prefix("merge_inputs");
        fs::create_dir_all(root.join("data/pos")).unwrap();
        fs::create_dir_all(root.join("data/neg")).unwrap();
        let pos = root.join("data/pos/pos.pcap");
        let neg = root.join("data/neg/neg.pcap");
        write_test_pcap(&pos);
        write_test_pcap(&neg);

        let prefix = unique_prefix("skip_mixed");
        let prefix_str = prefix.to_string_lossy().to_string();

        let _ = merge_pcap(&pos.to_string_lossy(), &neg.to_string_lossy(), &prefix_str, 1.0, false).unwrap();

        assert!(prefix.with_extension("data").exists());
        assert!(prefix.with_extension("label").exists());
        assert!(
            !prefix
                .parent()
                .unwrap()
                .join(format!("{}_mixed.pcap", prefix.file_name().unwrap().to_string_lossy()))
                .exists()
        );

        let _ = fs::remove_file(prefix.with_extension("data"));
        let _ = fs::remove_file(prefix.with_extension("label"));
        let _ = fs::remove_dir_all(root);
    }
}

#[derive(Clone, Debug, Default)]
struct FlowStat {
    pkts: u32,
    first_ts: u64,
    last_ts: u64,
}

fn list_files_from_pattern(pattern: &str) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in glob(pattern).context("Invalid glob pattern")? {
        files.push(entry?);
    }
    if files.is_empty() {
        let path = PathBuf::from(pattern);
        if path.exists() {
            files.push(path);
        } else {
            anyhow::bail!("No pcap files: {}", pattern);
        }
    }
    files.sort();
    Ok(files)
}

fn scan_flow_stats(pattern: &str, bidir: bool) -> Result<(HashMap<FlowKey, FlowStat>, u64, u64)> {
    let files = list_files_from_pattern(pattern)?;
    let mut map: HashMap<FlowKey, FlowStat> = HashMap::new();
    let mut min_ts: u64 = u64::MAX;
    let mut max_ts: u64 = 0;

    for f in files {
        let mut cap = Capture::from_file(&f)?;
        let lt = cap.get_datalink();
        while let Ok(pkt) = cap.next_packet() {
            let op = OwnedPacket::from_pcap(&pkt);
            let ts = op.timestamp_ns();
            if ts < min_ts {
                min_ts = ts;
            }
            if ts > max_ts {
                max_ts = ts;
            }

            if let Some(mut k) = parse_packet_to_key(&op, lt) {
                if bidir {
                    k = k.canonical();
                }

                let e = map.entry(k).or_insert_with(|| FlowStat {
                    pkts: 0,
                    first_ts: ts,
                    last_ts: ts,
                });
                e.pkts = e.pkts.saturating_add(1);
                if ts < e.first_ts {
                    e.first_ts = ts;
                }
                if ts > e.last_ts {
                    e.last_ts = ts;
                }
            }
        }
    }

    if min_ts == u64::MAX {
        min_ts = 0;
    }
    Ok((map, min_ts, max_ts))
}

fn weight_atk(pkts: u32) -> f64 {
    (1.0 + pkts as f64).ln()
}
fn weight_ben(pkts: u32) -> f64 {
    1.0 / (pkts as f64).sqrt().max(1.0)
}

fn select_flows_by_budget(
    stats: &HashMap<FlowKey, FlowStat>,
    min_ts: u64,
    max_ts: u64,
    total_budget_pkts: u64,
    time_bins: usize,
    is_attack: bool,
) -> HashSet<FlowKey> {
    let mut selected: HashSet<FlowKey> = HashSet::new();
    if total_budget_pkts == 0 || stats.is_empty() {
        return selected;
    }

    let k = time_bins.max(1);
    let span = max_ts.saturating_sub(min_ts).max(1);

    let mut bins: Vec<Vec<(FlowKey, u32, f64)>> = vec![Vec::new(); k];
    for (fk, st) in stats.iter() {
        let rel = st.first_ts.saturating_sub(min_ts);
        let b = ((rel as u128 * k as u128) / span as u128) as usize;
        let b = b.min(k - 1);
        let w = if is_attack {
            weight_atk(st.pkts)
        } else {
            weight_ben(st.pkts)
        };
        let u: f64 = rand::random::<f64>().max(1e-12);
        let key = -u.ln() / w.max(1e-12);
        bins[b].push((fk.clone(), st.pkts, key));
    }

    let per_bin = (total_budget_pkts / k as u64).max(1);
    let mut remaining = total_budget_pkts;

    for b in 0..k {
        bins[b].sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        let mut used_bin: u64 = 0;
        for (fk, pkts, _key) in bins[b].iter() {
            if remaining == 0 {
                break;
            }
            let p = *pkts as u64;
            if used_bin + p <= per_bin && p <= remaining {
                selected.insert(fk.clone());
                used_bin += p;
                remaining = remaining.saturating_sub(p);
            }
        }
    }

    if remaining > 0 {
        let mut all: Vec<(FlowKey, u32, f64)> = Vec::with_capacity(stats.len());
        for (fk, st) in stats.iter() {
            if selected.contains(fk) {
                continue;
            }
            let w = if is_attack {
                weight_atk(st.pkts)
            } else {
                weight_ben(st.pkts)
            };
            let u: f64 = rand::random::<f64>().max(1e-12);
            let key = -u.ln() / w.max(1e-12);
            all.push((fk.clone(), st.pkts, key));
        }
        all.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        for (fk, pkts, _key) in all.iter() {
            let p = *pkts as u64;
            if p <= remaining {
                selected.insert(fk.clone());
                remaining -= p;
                if remaining == 0 {
                    break;
                }
            }
        }
    }
    selected
}

fn next_selected_packet(
    stream: &mut PcapStreamer,
    selected: &HashSet<FlowKey>,
    bidir: bool,
    remaining_budget: &mut u64,
) -> Option<(OwnedPacket, Linktype)> {
    while *remaining_budget > 0 {
        let (pkt, lt) = stream.next_packet_with_linktype()?;
        if let Some(mut k) = parse_packet_to_key(&pkt, lt) {
            if bidir {
                k = k.canonical();
            }
            if selected.contains(&k) {
                *remaining_budget = remaining_budget.saturating_sub(1);
                return Some((pkt, lt));
            }
        }
    }
    None
}
