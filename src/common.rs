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

#[derive(Debug, Deserialize)]
pub struct GlobalConfig {
    pub raw_pcap: String,
    pub workspace_dir: String,
    #[serde(default = "default_sampling_rate")]
    pub benign_sampling_rate: f64,
}

pub fn default_sampling_rate() -> f64 {
    1.0
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
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub config: String,
}

/// 原始数据包结构
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto_code: u16,
    pub ts_ns: i64,
    pub len: u16,
    pub label: bool,
}

/// 流的唯一标识
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

/// 最终输出的流特征
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
