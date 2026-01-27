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

// =============================================================================
// 1. 定义 Merge Trait
// =============================================================================

pub trait MergeStrategy {
    fn execute(&self, output_path: &str) -> Result<usize>;
}

// =============================================================================
// 2. 策略一：基于哈希的一致性采样
// =============================================================================

pub struct HashSamplingStrategy {
    attack_pattern: String,
    benign_pattern: String,
    sampling_rate: f64,
}

impl HashSamplingStrategy {
    pub fn new(attack_pattern: &str, benign_pattern: &str, sampling_rate: f64) -> Self {
        Self {
            attack_pattern: attack_pattern.to_string(),
            benign_pattern: benign_pattern.to_string(),
            sampling_rate,
        }
    }
}

impl MergeStrategy for HashSamplingStrategy {
    fn execute(&self, output_path: &str) -> Result<usize> {
        info!(
            "🚀 Running Merge: Hash-based Sampling Mode (Rate: {:.2})",
            self.sampling_rate
        );

        // 1. 初始化输入流
        let mut atk_stream = PcapStreamer::new(&self.attack_pattern, false)?;
        let mut ben_stream = PcapStreamer::new(&self.benign_pattern, true)?;
        ben_stream.scan_duration()?; // 背景流量需要循环播放，需扫描时长

        let out_linktype = atk_stream.get_datalink().unwrap_or(Linktype::ETHERNET);
        atk_stream.open_next()?;
        ben_stream.open_next()?;

        // 2. 准备输出
        let cap_dead = Capture::dead(out_linktype)?;
        let mut writer = cap_dead.savefile(output_path)?;

        // 3. 初始化当前包
        let mut curr_atk = match atk_stream.next_packet() {
            Some(p) => p,
            None => {
                warn!("⚠️ Attack pcap is empty.");
                return Ok(0);
            },
        };

        // 时间对齐：将背景流量对齐到攻击开始前的一点点
        let atk_start_ns = curr_atk.timestamp_ns();
        let cycle_base_ns = atk_start_ns.saturating_sub(ben_stream.duration_ns / 10);
        let mut curr_ben = ben_stream.next_packet();

        let mut rng = rand::thread_rng();
        let mut count = 0;

        // 计算哈希阈值 (确定性采样)
        let hash_threshold = (u64::MAX as f64 * self.sampling_rate) as u64;

        // 4. 归并循环
        loop {
            // 计算背景包当前的虚拟时间戳
            let ben_ts = match &curr_ben {
                Some(b) => {
                    cycle_base_ns
                        + b.timestamp_ns().saturating_sub(ben_stream.base_start_ns)
                        + ben_stream.loop_offset_ns
                },
                None => u64::MAX,
            };
            let atk_ts = curr_atk.timestamp_ns();

            if atk_ts <= ben_ts {
                // Case A: 攻击包 (始终保留)
                curr_atk.set_timestamp(atk_ts);
                writer.write(&Packet {
                    header: &curr_atk.header,
                    data: &curr_atk.data,
                });
                count += 1;
                match atk_stream.next_packet() {
                    Some(p) => curr_atk = p,
                    None => break,
                }
            } else if let Some(mut b) = curr_ben {
                // Case B: 背景包 (哈希采样)
                let should_keep = if self.sampling_rate >= 1.0 {
                    true
                } else if let Some(key) = parse_packet_to_key(&b) {
                    key.canonical().get_hash() < hash_threshold
                } else {
                    rng.gen_bool(self.sampling_rate)
                };

                if should_keep {
                    b.set_timestamp(ben_ts);
                    writer.write(&Packet {
                        header: &b.header,
                        data: &b.data,
                    });
                    count += 1;
                }
                curr_ben = ben_stream.next_packet();
            } else {
                break;
            }
        }
        Ok(count)
    }
}

// =============================================================================
// 3. 策略二：基于预算的流规划 (Budget Control Mode)
// =============================================================================

pub struct BudgetControlStrategy {
    attack_pattern: String,
    benign_pattern: String,
    total_pkts: u64,
    attack_ratio: f64,
    time_bins: usize,
    bidirectional: bool,
}

impl BudgetControlStrategy {
    pub fn new(
        attack_pattern: &str,
        benign_pattern: &str,
        total_pkts: u64,
        attack_ratio: f64,
        time_bins: usize,
        bidirectional: bool,
    ) -> Self {
        Self {
            attack_pattern: attack_pattern.to_string(),
            benign_pattern: benign_pattern.to_string(),
            total_pkts,
            attack_ratio,
            time_bins,
            bidirectional,
        }
    }
}

impl MergeStrategy for BudgetControlStrategy {
    fn execute(&self, output_path: &str) -> Result<usize> {
        info!(
            "🚀 Running Merge: Budget Control Mode (Total: {}, Attack Ratio: {:.2})",
            self.total_pkts, self.attack_ratio
        );

        // 1. 预算计算
        let r_atk = self.attack_ratio.clamp(0.0, 1.0);
        let b_atk = ((self.total_pkts as f64) * r_atk).floor() as u64;
        let b_ben = self.total_pkts.saturating_sub(b_atk);

        // 2. 扫描统计 (Pass 1)
        info!("   -> Scanning flow stats...");
        let (atk_stats, atk_min, atk_max) = scan_flow_stats(&self.attack_pattern, self.bidirectional)?;
        let (ben_stats, ben_min, ben_max) = scan_flow_stats(&self.benign_pattern, self.bidirectional)?;

        let min_ts = atk_min.min(ben_min);
        let max_ts = atk_max.max(ben_max);

        // 3. 流选择规划
        info!("   -> Selecting flows...");
        let selected_atk = select_flows_by_budget(&atk_stats, min_ts, max_ts, b_atk, self.time_bins, true);
        let selected_ben = select_flows_by_budget(&ben_stats, min_ts, max_ts, b_ben, self.time_bins, false);

        // 4. 重放合并 (Pass 2)
        let mut atk_stream = PcapStreamer::new(&self.attack_pattern, false)?;
        let mut ben_stream = PcapStreamer::new(&self.benign_pattern, true)?;
        ben_stream.scan_duration()?;

        let out_linktype = atk_stream.get_datalink().unwrap_or(Linktype::ETHERNET);
        atk_stream.open_next()?;
        ben_stream.open_next()?;

        let cap_dead = Capture::dead(out_linktype)?;
        let mut writer = cap_dead.savefile(output_path)?;

        let mut atk_budget_left = b_atk;
        let mut ben_budget_left = b_ben;

        // 初始化第一个选中的包
        let mut curr_atk =
            match next_selected_packet(&mut atk_stream, &selected_atk, self.bidirectional, &mut atk_budget_left) {
                Some(p) => p,
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

        // 归并循环 (Budget Mode)
        loop {
            let ben_ts = match &curr_ben {
                Some(b) => {
                    cycle_base_ns
                        + b.timestamp_ns().saturating_sub(ben_stream.base_start_ns)
                        + ben_stream.loop_offset_ns
                },
                None => u64::MAX,
            };
            let atk_ts = curr_atk.timestamp_ns();

            if atk_ts <= ben_ts {
                curr_atk.set_timestamp(atk_ts);
                writer.write(&Packet {
                    header: &curr_atk.header,
                    data: &curr_atk.data,
                });
                count += 1;
                match next_selected_packet(&mut atk_stream, &selected_atk, self.bidirectional, &mut atk_budget_left) {
                    Some(p) => curr_atk = p,
                    None => break, // 攻击流用完或预算耗尽
                }
            } else if let Some(mut b) = curr_ben {
                b.set_timestamp(ben_ts);
                writer.write(&Packet {
                    header: &b.header,
                    data: &b.data,
                });
                count += 1;
                curr_ben =
                    next_selected_packet(&mut ben_stream, &selected_ben, self.bidirectional, &mut ben_budget_left);
            } else {
                break;
            }
        }

        // 补齐背景流量 (可选)
        while let Some(mut b) = curr_ben {
            let ben_ts =
                cycle_base_ns + b.timestamp_ns().saturating_sub(ben_stream.base_start_ns) + ben_stream.loop_offset_ns;
            b.set_timestamp(ben_ts);
            writer.write(&Packet {
                header: &b.header,
                data: &b.data,
            });
            count += 1;
            curr_ben = next_selected_packet(&mut ben_stream, &selected_ben, self.bidirectional, &mut ben_budget_left);
        }

        Ok(count)
    }
}

// =============================================================================
// 4. 工厂入口 / 主函数
// =============================================================================

/// 对外暴露的统一入口
pub fn merge_pcap(attack_pattern: &str, benign_pattern: &str, output: &str, sampling_rate: f64) -> Result<usize> {
    // 环境变量读取
    let controlled_total_pkts = env::var("PCAP_MERGE_TOTAL_PKTS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let controlled_attack_ratio = env::var("PCAP_MERGE_ATTACK_RATIO")
        .ok()
        .and_then(|v| v.parse::<f64>().ok());

    // 策略选择工厂逻辑
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
                attack_pattern,
                benign_pattern,
                total,
                ratio,
                bins,
                bidir,
            ))
        } else {
            Box::new(HashSamplingStrategy::new(attack_pattern, benign_pattern, sampling_rate))
        };

    // 执行策略
    strategy.execute(output)
}

// =============================================================================
// 5. 基础设施 & 辅助函数
// =============================================================================

// OwnedPacket: 用于在内存中持有数据包所有权的结构体
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
    fn timestamp_ns(&self) -> u64 {
        (self.header.ts.tv_sec as u64) * 1_000_000_000 + (self.header.ts.tv_usec as u64) * 1_000
    }
    fn set_timestamp(&mut self, ts_ns: u64) {
        self.header.ts.tv_sec = (ts_ns / 1_000_000_000) as _;
        self.header.ts.tv_usec = ((ts_ns % 1_000_000_000) / 1_000) as _;
    }
}

// PcapStreamer: 处理多文件读取和循环播放
struct PcapStreamer {
    files: Vec<PathBuf>,
    current_file_idx: usize,
    capture: Option<Capture<Offline>>,
    is_looping: bool,
    duration_ns: u64,
    loop_offset_ns: u64,
    base_start_ns: u64,
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
        self.capture = Some(Capture::from_file(&self.files[self.current_file_idx])?);
        self.current_file_idx += 1;
        Ok(true)
    }

    fn next_packet(&mut self) -> Option<OwnedPacket> {
        loop {
            if self.capture.is_none() {
                if !self.open_next().unwrap_or(false) {
                    return None;
                }
            }
            match self.capture.as_mut().unwrap().next_packet() {
                Ok(pkt) => {
                    return Some(OwnedPacket::from_pcap(&pkt));
                },
                Err(pcap::Error::NoMorePackets) => {
                    self.capture = None;
                    continue;
                },
                _ => return None,
            }
        }
    }

    fn get_datalink(&self) -> Result<Linktype> {
        if self.files.is_empty() {
            anyhow::bail!("No files to check linktype");
        }
        let cap = Capture::from_file(&self.files[0])?;
        Ok(cap.get_datalink())
    }
}

// ... 辅助函数 parse_packet_to_key (必须适配 common::FlowKey) ...
fn parse_packet_to_key(pkt: &OwnedPacket) -> Option<FlowKey> {
    let data = &pkt.data;
    if data.len() < 14 {
        return None;
    }

    // 简单解析 Ethernet Header
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0800 => {
            // IPv4
            if data.len() < 34 {
                return None;
            } // 14(Eth) + 20(IP)
            let ip = &data[14..];
            let ver_ihl = ip[0];
            let ver = ver_ihl >> 4;
            if ver != 4 {
                return None;
            }
            let ihl = (ver_ihl & 0x0F) as usize * 4;
            if ip.len() < ihl + 4 {
                return None;
            } // IP header + 4 bytes for ports

            let proto = ip[9];

            // 提取 IP 地址
            let src_ip = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));

            // 提取端口 (仅针对 TCP/UDP)
            let mut sport = 0u16;
            let mut dport = 0u16;
            if proto == 6 || proto == 17 {
                let l4 = &ip[ihl..];
                if l4.len() >= 4 {
                    sport = u16::from_be_bytes([l4[0], l4[1]]);
                    dport = u16::from_be_bytes([l4[2], l4[3]]);
                }
            }

            // 使用 common::FlowKey::new
            Some(FlowKey::new(src_ip, dst_ip, sport, dport, proto))
        },
        0x86DD => {
            // IPv6
            if data.len() < 54 {
                return None;
            } // 14(Eth) + 40(IP)
            let ip = &data[14..];
            let ver = ip[0] >> 4;
            if ver != 6 {
                return None;
            }

            let proto = ip[6]; // Next Header

            // 提取 IPv6 地址 (需要拷贝字节数组)
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&ip[8..24]);
            dst_bytes.copy_from_slice(&ip[24..40]);

            let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

            let mut sport = 0u16;
            let mut dport = 0u16;
            if proto == 6 || proto == 17 {
                // 简化处理：假设没有 IPv6 Extension Headers
                let l4 = &ip[40..];
                if l4.len() >= 4 {
                    sport = u16::from_be_bytes([l4[0], l4[1]]);
                    dport = u16::from_be_bytes([l4[2], l4[3]]);
                }
            }

            Some(FlowKey::new(src_ip, dst_ip, sport, dport, proto))
        },
        _ => None, // 非 IP 流量 (ARP, etc.)
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
        while let Ok(pkt) = cap.next_packet() {
            let op = OwnedPacket::from_pcap(&pkt);
            let ts = op.timestamp_ns();
            if ts < min_ts {
                min_ts = ts;
            }
            if ts > max_ts {
                max_ts = ts;
            }

            if let Some(mut k) = parse_packet_to_key(&op) {
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
) -> Option<OwnedPacket> {
    while *remaining_budget > 0 {
        let pkt = stream.next_packet()?;
        if let Some(mut k) = parse_packet_to_key(&pkt) {
            if bidir {
                k = k.canonical();
            }
            if selected.contains(&k) {
                *remaining_budget = remaining_budget.saturating_sub(1);
                return Some(pkt);
            }
        }
        // not selected => skip
    }
    None
}
