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

#[derive(Deserialize, Clone, Debug)]
pub struct PretrainFamilyConfig {
    pub family: String,
    pub glob: Option<String>,
    pub shared_pcap: Option<String>,
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
    pub pretrain_families: Option<Vec<PretrainFamilyConfig>>,

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
        data: Option<String>,
        #[arg(long)]
        out_dir: Option<String>,
        #[arg(long)]
        manifest: Option<String>,
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
        max_flows: usize,
        #[arg(long, default_value_t = 256)]
        timeout_check_interval: usize,
        #[arg(long, default_value_t = 5)]
        graph_token_count: usize,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn deserializes_legacy_pretrain_config_without_families() {
        let config: Config = serde_json::from_str(
            r#"{
                "global": {
                    "mode": "folder",
                    "output_dir": "out",
                    "pos_glob": "pos/*.pcap",
                    "neg_glob": "neg/*.pcap",
                    "shared_neg_pcap": null,
                    "pretrain_neg_glob": "pretrain/*.pcap",
                    "shared_pretrain_neg_pcap": null,
                    "raw_pcap": null,
                    "neg_sampling_rate": 1.0,
                    "write_mixed_pcap": false
                },
                "attacks": []
            }"#,
        )
        .expect("legacy config should deserialize");

        assert_eq!(config.global.pretrain_neg_glob.as_deref(), Some("pretrain/*.pcap"));
        assert!(config.global.pretrain_families.is_none());
    }

    #[test]
    fn deserializes_dataset_level_pretrain_families() {
        let config: Config = serde_json::from_str(
            r#"{
                "global": {
                    "mode": "folder",
                    "output_dir": "out",
                    "pos_glob": null,
                    "neg_glob": null,
                    "shared_neg_pcap": null,
                    "pretrain_neg_glob": null,
                    "shared_pretrain_neg_pcap": null,
                    "pretrain_families": [
                        {
                            "family": "benign-web",
                            "glob": "families/web/*.pcap",
                            "shared_pcap": null
                        },
                        {
                            "family": "benign-dns",
                            "glob": null,
                            "shared_pcap": "cache/dns.pcap"
                        }
                    ],
                    "raw_pcap": null,
                    "neg_sampling_rate": 1.0,
                    "write_mixed_pcap": false
                },
                "attacks": []
            }"#,
        )
        .expect("family config should deserialize");

        let families = config.global.pretrain_families.expect("families should be present");
        assert_eq!(families.len(), 2);
        assert_eq!(families[0].family, "benign-web");
        assert_eq!(families[0].glob.as_deref(), Some("families/web/*.pcap"));
        assert_eq!(families[1].shared_pcap.as_deref(), Some("cache/dns.pcap"));
    }

    #[test]
    fn pretrain_cache_accepts_manifest_without_data_or_out_dir() {
        let args = Args::try_parse_from(["pcap_processor", "pretrain-cache", "--manifest", "manifest.json"])
            .expect("manifest mode should parse without data or out-dir");

        match args.command {
            Command::PretrainCache {
                data,
                out_dir,
                manifest,
                packet_cutoff,
                flow_timeout_s,
                window_duration_s,
                window_packet_limit,
                shard_flows,
                max_flows,
                timeout_check_interval,
                graph_token_count,
            } => {
                assert!(data.is_none());
                assert!(out_dir.is_none());
                assert_eq!(manifest.as_deref(), Some("manifest.json"));
                assert_eq!(packet_cutoff, 20);
                assert_eq!(flow_timeout_s, 60);
                assert_eq!(window_duration_s, 300);
                assert_eq!(window_packet_limit, 2000);
                assert_eq!(shard_flows, 50000);
                assert_eq!(max_flows, 0);
                assert_eq!(timeout_check_interval, 256);
                assert_eq!(graph_token_count, 5);
            },
            _ => panic!("expected pretrain-cache command"),
        }
    }

    #[test]
    fn pretrain_cache_keeps_legacy_data_and_out_dir_mode() {
        let args = Args::try_parse_from([
            "pcap_processor",
            "pretrain-cache",
            "--data",
            "train.data",
            "--out-dir",
            "cache",
        ])
        .expect("legacy data/out-dir mode should parse");

        match args.command {
            Command::PretrainCache {
                data,
                out_dir,
                manifest,
                ..
            } => {
                assert_eq!(data.as_deref(), Some("train.data"));
                assert_eq!(out_dir.as_deref(), Some("cache"));
                assert!(manifest.is_none());
            },
            _ => panic!("expected pretrain-cache command"),
        }
    }
}
