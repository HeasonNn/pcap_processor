use clap::Parser;
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub attacks: Vec<AttackConfig>,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct GlobalConfig {
    pub mode: String, // "folder" | "rules"
    pub output_dir: String,

    // folder 模式
    pub pos_glob: Option<String>,
    pub neg_glob: Option<String>,
    pub shared_neg_pcap: Option<String>,
    pub pretrain_neg_glob: Option<String>,
    pub shared_pretrain_neg_pcap: Option<String>,

    // rules 模式
    pub raw_pcap: Option<String>,

    // HashSampling
    pub neg_sampling_rate: f64, // 只对 neg 采样

    // 输出 mixed.pcap 是否需要
    pub write_mixed_pcap: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct AttackConfig {
    pub name: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub attackers: Vec<String>,
    pub start_time: String,
    pub end_time: String,
    pub attack_type: String,
    pub direction: Option<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Process pcap files and generate dataset
    Process {
        #[arg(short, long)]
        config: String,
    },
    /// Generate statistics from raw pcap files
    Stats {
        #[arg(short, long)]
        config: String,
        #[arg(short, long)]
        output: String,
    },
    /// Build cached token shards for pretraining from a .data file
    PretrainCache {
        #[arg(long)]
        data: String,
        #[arg(long)]
        out_dir: String,
        #[arg(long, default_value = "")]
        source_name: String,
        #[arg(long, default_value_t = 0)]
        source_id: i16,
        #[arg(long, default_value_t = 20)]
        packet_cutoff: usize,
        #[arg(long, default_value_t = 60)]
        flow_timeout_s: u64,
        #[arg(long, default_value_t = 300)]
        window_duration_s: u64,
        #[arg(long, default_value_t = 2000)]
        window_packet_limit: usize,
        #[arg(long, default_value_t = 50000)]
        shard_flows: usize,
        #[arg(long, default_value_t = 0)]
        max_packets: usize,
        #[arg(long, default_value_t = 0)]
        max_flows: usize,
        #[arg(long, default_value_t = 256)]
        timeout_check_interval: usize,
        #[arg(long, default_value_t = 5)]
        graph_token_count: usize,
        #[arg(long, default_value = "ns")]
        timestamp_unit: String,
        #[arg(long, default_value = "protocol")]
        field7_mode: String,
    },
    /// Build cached token shards for few-shot fine-tuning from .data/.label files
    FinetuneCache {
        #[arg(long)]
        data: String,
        #[arg(long)]
        labels: String,
        #[arg(long)]
        out_dir: String,
        #[arg(long)]
        source_name: String,
        #[arg(long, default_value_t = 20)]
        packet_cutoff: usize,
        #[arg(long, default_value_t = 60)]
        flow_timeout_s: u64,
        #[arg(long, default_value_t = 300)]
        window_duration_s: u64,
        #[arg(long, default_value_t = 100000)]
        window_packet_limit: usize,
        #[arg(long, default_value_t = 4096)]
        shard_flows: usize,
        #[arg(long, default_value_t = 0)]
        max_packets: usize,
        #[arg(long, default_value_t = 256)]
        timeout_check_interval: usize,
        #[arg(long, default_value_t = 5)]
        graph_token_count: usize,
        #[arg(long, default_value = "ns")]
        timestamp_unit: String,
        #[arg(long, default_value = "protocol")]
        field7_mode: String,
        #[arg(long, default_value_t = false)]
        attack_centered: bool,
        #[arg(long, default_value = "flow_contaminated")]
        label_policy: String,
        #[arg(long, default_value_t = 20000)]
        normal_flow_sample_size: usize,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packet_code: u16,
    pub ts_ns: i64,
    pub len: u16,
    pub label: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, proto: u8) -> Self {
        Self {
            src_ip: src,
            dst_ip: dst,
            src_port: sport,
            dst_port: dport,
            protocol: proto,
        }
    }

    pub fn canonical(&self) -> Self {
        let (src, dst, sport, dport) =
            if self.src_ip > self.dst_ip || (self.src_ip == self.dst_ip && self.src_port > self.dst_port) {
                (self.dst_ip, self.src_ip, self.dst_port, self.src_port)
            } else {
                (self.src_ip, self.dst_ip, self.src_port, self.dst_port)
            };
        Self {
            src_ip: src,
            dst_ip: dst,
            src_port: sport,
            dst_port: dport,
            protocol: self.protocol,
        }
    }

    pub fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }
}

pub enum PacketType {
    PktTypeIpv4,
    PktTypeIpv6,
    PktTypeIcmp,
    PktTypeIgmp,
    PktTypeTcpSyn,
    PktTypeTcpAck,
    PktTypeTcpFin,
    PktTypeTcpRst,
    PktTypeUdp,
    PktTypeUnknown,
}

#[derive(Debug)]
pub struct PacketMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packet_code: u16,
    pub ip_len: u16,
    pub ts_ns: i64,
}

#[allow(dead_code)]
impl PacketMeta {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        packet_code: u16,
        ip_len: u16,
        ts_ns: i64,
    ) -> Self {
        Self {
            src_ip: (src_ip),
            dst_ip: (dst_ip),
            src_port: (src_port),
            dst_port: (dst_port),
            protocol: (protocol),
            packet_code: (packet_code),
            ip_len: (ip_len),
            ts_ns: (ts_ns),
        }
    }

    pub fn to_pkt_code(t: PacketType) -> u16 {
        1 << (t as u8)
    }

    pub fn set_pkt_code(code: &mut u16, t: PacketType) {
        *code |= Self::to_pkt_code(t);
    }
}

#[derive(Debug)]
pub struct FlowFeature {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub start_ts: i64,
    pub duration: f64,
    pub byteps: f64,
    pub pps: f64,
    pub pkt_len_mean: f64,
    pub pkt_len_std: f64,
    pub iat_mean: f64,
    pub iat_std: f64,
    pub fwd_pkts: u32,
    pub bwd_pkts: u32,
    pub fwd_seg_size: f64,
    pub bwd_seg_size: f64,
    pub label: bool,
}
