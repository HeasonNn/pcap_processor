use anyhow::{Context, Result};
use pcap::Capture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use tempfile::TempDir;
use zip::ZipArchive;

use crate::common::FlowKey;
use crate::common::PacketMeta;
use crate::parser::parse_packet;

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsConfig {
    pub name: String,
    pub sources: Vec<String>,
    pub rules: Option<String>,
    pub timezone_offset: Option<i32>,
}

#[derive(Debug, Default)]
struct FlowStats {
    packets: usize,
    bytes: u64,
}

#[derive(Debug, Default)]
struct Accumulator {
    benign_flows: HashMap<FlowKey, FlowStats>,
    attack_flows: HashMap<FlowKey, FlowStats>,
    benign_packets: usize,
    attack_packets: usize,
    benign_bytes: u64,
    attack_bytes: u64,
    benign_proto: HashMap<u8, usize>,
    attack_proto: HashMap<u8, usize>,
    benign_dport: HashMap<u16, usize>,
    attack_dport: HashMap<u16, usize>,
    skipped: usize,
}

#[derive(Debug, Serialize)]
pub struct DatasetStats {
    pub name: String,
    pub benign_packets: usize,
    pub attack_packets: usize,
    pub benign_flows: usize,
    pub attack_flows: usize,
    pub benign_bytes: u64,
    pub attack_bytes: u64,
    pub attack_packet_ratio: f64,
    pub attack_flow_ratio: f64,
    pub avg_pkts_per_benign_flow: f64,
    pub avg_pkts_per_attack_flow: f64,
    pub benign_proto_top: Vec<(u8, usize)>,
    pub attack_proto_top: Vec<(u8, usize)>,
    pub benign_dport_top: Vec<(u16, usize)>,
    pub attack_dport_top: Vec<(u16, usize)>,
    pub skipped: usize,
}

type RuleIndex = HashMap<IpAddr, Vec<(f64, f64, String, String)>>;

pub fn run_stats(config_path: &str, output_path: &str) -> Result<()> {
    let config_content = std::fs::read_to_string(config_path).context("Failed to read config file")?;
    let configs: Vec<StatsConfig> = serde_json::from_str(&config_content).context("Failed to parse config JSON")?;

    let mut results = Vec::new();

    for cfg in configs {
        log::info!("Processing dataset: {}", cfg.name);

        let rule_index = if let Some(rules_path) = &cfg.rules {
            let offset = cfg.timezone_offset.unwrap_or(0) as f64 * 3600.0;
            load_rules(rules_path, offset)?
        } else {
            HashMap::new()
        };

        let mut accum = Accumulator::default();

        for source in &cfg.sources {
            process_source(source, &rule_index, &mut accum)?;
        }

        let total_packets = accum.benign_packets + accum.attack_packets;
        let total_flows = accum.benign_flows.len() + accum.attack_flows.len();

        let stats = DatasetStats {
            name: cfg.name.clone(),
            benign_packets: accum.benign_packets,
            attack_packets: accum.attack_packets,
            benign_flows: accum.benign_flows.len(),
            attack_flows: accum.attack_flows.len(),
            benign_bytes: accum.benign_bytes,
            attack_bytes: accum.attack_bytes,
            attack_packet_ratio: if total_packets > 0 {
                accum.attack_packets as f64 / total_packets as f64
            } else {
                0.0
            },
            attack_flow_ratio: if total_flows > 0 {
                accum.attack_flows.len() as f64 / total_flows as f64
            } else {
                0.0
            },
            avg_pkts_per_benign_flow: if !accum.benign_flows.is_empty() {
                accum.benign_packets as f64 / accum.benign_flows.len() as f64
            } else {
                0.0
            },
            avg_pkts_per_attack_flow: if !accum.attack_flows.is_empty() {
                accum.attack_packets as f64 / accum.attack_flows.len() as f64
            } else {
                0.0
            },
            benign_proto_top: top_n(&accum.benign_proto, 10),
            attack_proto_top: top_n(&accum.attack_proto, 10),
            benign_dport_top: top_n(&accum.benign_dport, 20),
            attack_dport_top: top_n(&accum.attack_dport, 20),
            skipped: accum.skipped,
        };

        log::info!(
            "Done {}: {} benign pkts, {} attack pkts, {} benign flows, {} attack flows",
            cfg.name,
            stats.benign_packets,
            stats.attack_packets,
            stats.benign_flows,
            stats.attack_flows
        );

        results.push(stats);
    }

    let output = serde_json::to_string_pretty(&results)?;
    std::fs::write(output_path, output)?;
    log::info!("Results written to: {}", output_path);

    Ok(())
}

fn process_source(source: &str, rule_index: &RuleIndex, accum: &mut Accumulator) -> Result<()> {
    let path = Path::new(source);

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            process_path(&p, rule_index, accum)?;
        }
    } else {
        process_path(path, rule_index, accum)?;
    }

    Ok(())
}

fn process_path(path: &Path, rule_index: &RuleIndex, accum: &mut Accumulator) -> Result<()> {
    match path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        Some(ext) if ext == "pcap" || ext == "pcapng" => {
            log::info!("Scanning: {}", path.display());
            process_pcap(path, rule_index, accum)?;
        },
        Some(ext) if ext == "zip" => {
            log::info!("Scanning zip: {}", path.display());
            process_zip(path, rule_index, accum)?;
        },
        _ => {
            log::warn!("Skipping unsupported source: {}", path.display());
        },
    }

    Ok(())
}

fn process_zip(path: &Path, rule_index: &RuleIndex, accum: &mut Accumulator) -> Result<()> {
    let file = File::open(path).with_context(|| format!("Failed to open zip: {}", path.display()))?;
    let mut archive =
        ZipArchive::new(file).with_context(|| format!("Failed to read zip archive: {}", path.display()))?;
    let temp_dir = TempDir::new().context("Failed to create temp dir for zip extraction")?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("Failed to read zip entry {} from {}", i, path.display()))?;
        let member_name = entry.name().to_string();
        let member_name_lower = member_name.to_ascii_lowercase();
        if !(member_name_lower.ends_with(".pcap") || member_name_lower.ends_with(".pcapng")) {
            continue;
        }

        let file_name = Path::new(&member_name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("member.pcap");
        let out_path = temp_dir.path().join(file_name);
        {
            let mut out = File::create(&out_path)
                .with_context(|| format!("Failed to create extracted file: {}", out_path.display()))?;
            io::copy(&mut entry, &mut out).with_context(|| format!("Failed to extract zip entry {}", member_name))?;
        }

        log::info!("Scanning extracted: {}:{}", path.display(), member_name);
        process_pcap(&out_path, rule_index, accum)?;
    }

    Ok(())
}

fn process_pcap(path: &Path, rule_index: &RuleIndex, accum: &mut Accumulator) -> Result<()> {
    let mut cap = match Capture::from_file(path) {
        Ok(cap) => cap,
        Err(err) => {
            accum.skipped += 1;
            log::warn!("Skipping unreadable pcap {}: {}", path.display(), err);
            return Ok(());
        },
    };

    let link_type = cap.get_datalink();

    while let Ok(packet) = cap.next_packet() {
        let Some(meta) = parse_packet(&packet, link_type) else {
            accum.skipped += 1;
            continue;
        };

        let ts_f64 = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        let is_attack = match_rule(rule_index, &meta, ts_f64);

        let key = FlowKey::new(meta.src_ip, meta.dst_ip, meta.src_port, meta.dst_port, meta.protocol).canonical();

        if is_attack {
            accum.attack_packets += 1;
            accum.attack_bytes += meta.ip_len as u64;
            *accum.attack_proto.entry(meta.protocol).or_insert(0) += 1;
            *accum.attack_dport.entry(meta.dst_port).or_insert(0) += 1;

            let flow_stat = accum.attack_flows.entry(key).or_insert_with(FlowStats::default);
            flow_stat.packets += 1;
            flow_stat.bytes += meta.ip_len as u64;
        } else {
            accum.benign_packets += 1;
            accum.benign_bytes += meta.ip_len as u64;
            *accum.benign_proto.entry(meta.protocol).or_insert(0) += 1;
            *accum.benign_dport.entry(meta.dst_port).or_insert(0) += 1;

            let flow_stat = accum.benign_flows.entry(key).or_insert_with(FlowStats::default);
            flow_stat.packets += 1;
            flow_stat.bytes += meta.ip_len as u64;
        }
    }

    Ok(())
}

fn load_rules(rules_path: &str, timezone_offset: f64) -> Result<RuleIndex> {
    let content = std::fs::read_to_string(rules_path).context("Failed to read rules file")?;

    #[derive(Deserialize)]
    struct RulesFile {
        attacks: Vec<Attack>,
    }

    #[derive(Deserialize)]
    struct Attack {
        rules: Vec<Rule>,
    }

    #[derive(Deserialize)]
    struct Rule {
        attackers: Vec<String>,
        start_time: String,
        end_time: String,
        attack_type: Option<String>,
        direction: Option<String>,
    }

    let rules_file: RulesFile = serde_json::from_str(&content).context("Failed to parse rules JSON")?;

    let mut index: RuleIndex = HashMap::new();

    for attack in rules_file.attacks {
        for rule in attack.rules {
            let start = parse_time(&rule.start_time)? + timezone_offset;
            let end = parse_time(&rule.end_time)? + timezone_offset;
            let attack_type = rule.attack_type.unwrap_or_else(|| "attack".to_string());
            let direction = rule.direction.unwrap_or_else(|| "either".to_string()).to_lowercase();

            for ip_str in &rule.attackers {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    index
                        .entry(ip)
                        .or_insert_with(Vec::new)
                        .push((start, end, attack_type.clone(), direction.clone()));
                }
            }
        }
    }

    Ok(index)
}

fn parse_time(s: &str) -> Result<f64> {
    use chrono::NaiveDateTime;

    let fmts = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"];
    for fmt in fmts {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(dt.and_utc().timestamp() as f64);
        }
    }
    anyhow::bail!("Invalid time format: {}", s)
}

fn match_rule(index: &RuleIndex, meta: &PacketMeta, ts: f64) -> bool {
    if let Some(rules) = index.get(&meta.src_ip) {
        if rules
            .iter()
            .any(|(s, e, _, dir)| ts >= *s && ts <= *e && (dir == "src" || dir == "either"))
        {
            return true;
        }
    }

    if let Some(rules) = index.get(&meta.dst_ip) {
        if rules
            .iter()
            .any(|(s, e, _, dir)| ts >= *s && ts <= *e && (dir == "dst" || dir == "either"))
        {
            return true;
        }
    }

    false
}

fn top_n<K: Ord + Copy>(map: &HashMap<K, usize>, n: usize) -> Vec<(K, usize)> {
    let mut vec: Vec<_> = map.iter().map(|(&k, &v)| (k, v)).collect();
    vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    vec.truncate(n);
    vec
}
