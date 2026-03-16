use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::str::FromStr;

use crate::common::{FlowFeature, FlowKey, RawPacket};
use crate::export::CsvExporter;

const FLOW_TIMEOUT_NS: i64 = 120 * 1_000_000_000;

pub struct FlowEngine {
    batch_size: usize,
}

impl FlowEngine {
    pub fn new(batch_size: usize) -> Self {
        Self { batch_size }
    }

    pub fn run(&self, data_path: &str, label_path: &str, output_csv: &str) -> Result<()> {
        let file_data = File::open(data_path).context("Failed to open .data file")?;
        let file_label = File::open(label_path).context("Failed to open .label file")?;

        let mut reader_data = BufReader::new(file_data);
        let mut reader_label = BufReader::new(file_label);
        let mut exporter = CsvExporter::new(output_csv)?;

        let mut batch_idx = 0;
        let mut total_flows = 0;
        let mut lines_data = Vec::with_capacity(self.batch_size);
        let mut buf_label = Vec::with_capacity(self.batch_size);

        loop {
            batch_idx += 1;
            lines_data.clear();
            buf_label.clear();

            let mut line = String::new();
            while lines_data.len() < self.batch_size {
                line.clear();
                if reader_data.read_line(&mut line)? == 0 {
                    break;
                }
                lines_data.push(line.trim_end().to_string());

                let mut byte_buf = [0u8; 1];
                loop {
                    if reader_label.read(&mut byte_buf)? == 0 {
                        break;
                    }
                    let c = byte_buf[0];
                    if c == b'0' || c == b'1' {
                        buf_label.push(c == b'1');
                        break;
                    }
                }
            }

            if lines_data.is_empty() {
                break;
            }

            let valid_len = std::cmp::min(lines_data.len(), buf_label.len());
            log::info!("🔄 Processing Batch {}: {} packets...", batch_idx, valid_len);

            let packets: Vec<RawPacket> = lines_data[..valid_len]
                .par_iter()
                .zip(&buf_label[..valid_len])
                .filter_map(|(line, &label)| parse_line(line, label))
                .collect();

            let num_shards = rayon::current_num_threads();
            let mut shards: Vec<Vec<RawPacket>> = vec![Vec::new(); num_shards];

            for pkt in packets {
                let proto_u8 = decode_proto(pkt.proto_code);
                let key = FlowKey::new(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, proto_u8).canonical();

                let hash = key.get_hash();
                let shard_idx = (hash as usize) % num_shards;
                shards[shard_idx].push(pkt);
            }

            let batch_features: Vec<FlowFeature> =
                shards.into_par_iter().flat_map(|shard| process_shard(shard)).collect();

            for f in &batch_features {
                exporter.write_record(f)?;
            }

            total_flows += batch_features.len();
            log::info!("   -> Batch Done. Flows generated: {}", batch_features.len());
        }

        exporter.flush()?;
        log::info!("✅ Flow construction completed. Total flows: {}", total_flows);
        Ok(())
    }
}

fn parse_line(line: &str, label: bool) -> Option<RawPacket> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }

    Some(RawPacket {
        src_ip: IpAddr::from_str(parts[1]).ok()?,
        dst_ip: IpAddr::from_str(parts[2]).ok()?,
        src_port: u16::from_str(parts[3]).ok()?,
        dst_port: u16::from_str(parts[4]).ok()?,
        ts_ns: i64::from_str(parts[5]).ok()?,
        proto_code: u16::from_str(parts[6]).ok()?,
        len: u16::from_str(parts[7]).ok()?,
        label,
    })
}

fn process_shard(packets: Vec<RawPacket>) -> Vec<FlowFeature> {
    let mut flow_map: HashMap<FlowKey, FlowAccumulator> = HashMap::new();
    let mut completed_flows: Vec<FlowFeature> = Vec::new();

    for pkt in packets {
        let proto_u8 = decode_proto(pkt.proto_code);
        let key = FlowKey::new(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, proto_u8);

        let mut evicted = None;
        if let Some(acc) = flow_map.get(&key) {
            if pkt.ts_ns - acc.last_ts > FLOW_TIMEOUT_NS {
                evicted = flow_map.remove(&key);
            }
        }
        if let Some(acc) = evicted {
            completed_flows.push(acc.finalize());
        }

        let acc = flow_map
            .entry(key.clone())
            .or_insert_with(|| FlowAccumulator::new(&key, &pkt));
        acc.add_packet(&pkt);
    }

    for (_, acc) in flow_map {
        completed_flows.push(acc.finalize());
    }
    completed_flows
}

struct FlowAccumulator {
    key: FlowKey,
    start_ts: i64,
    last_ts: i64,
    total_bytes: u64,
    packet_count: u32,
    len_sum: f64,
    len_sq_sum: f64,
    iat_sum: f64,
    iat_sq_sum: f64,
    iat_count: u32,
    has_malicious: bool,
}

impl FlowAccumulator {
    fn new(key: &FlowKey, first_pkt: &RawPacket) -> Self {
        Self {
            key: key.clone(),
            start_ts: first_pkt.ts_ns,
            last_ts: first_pkt.ts_ns,
            total_bytes: 0,
            packet_count: 0,
            len_sum: 0.0,
            len_sq_sum: 0.0,
            iat_sum: 0.0,
            iat_sq_sum: 0.0,
            iat_count: 0,
            has_malicious: false,
        }
    }

    fn add_packet(&mut self, pkt: &RawPacket) {
        if self.packet_count > 0 {
            let iat = (pkt.ts_ns - self.last_ts) as f64 / 1e9;
            if iat >= 0.0 {
                self.iat_sum += iat;
                self.iat_sq_sum += iat * iat;
                self.iat_count += 1;
            }
        }
        self.last_ts = pkt.ts_ns;

        let l = pkt.len as f64;
        self.len_sum += l;
        self.len_sq_sum += l * l;
        self.total_bytes += pkt.len as u64;
        self.packet_count += 1;

        if pkt.label {
            self.has_malicious = true;
        }
    }

    fn finalize(self) -> FlowFeature {
        let duration = (self.last_ts - self.start_ts) as f64 / 1e9;

        let n = self.packet_count as f64;
        let len_mean = if n > 0.0 { self.len_sum / n } else { 0.0 };
        let len_std = if n > 1.0 {
            ((self.len_sq_sum / n) - (len_mean * len_mean)).sqrt().max(0.0)
        } else {
            0.0
        };

        let n_iat = self.iat_count as f64;
        let iat_mean = if n_iat > 0.0 { self.iat_sum / n_iat } else { 0.0 };
        let iat_std = if n_iat > 1.0 {
            ((self.iat_sq_sum / n_iat) - (iat_mean * iat_mean)).sqrt().max(0.0)
        } else {
            0.0
        };

        let (byteps, pps) = if duration > 1e-6 {
            (self.total_bytes as f64 / duration, self.packet_count as f64 / duration)
        } else {
            (0.0, 0.0)
        };

        FlowFeature {
            src_ip: self.key.src_ip,
            dst_ip: self.key.dst_ip,
            src_port: self.key.src_port,
            dst_port: self.key.dst_port,
            protocol: self.key.protocol,
            start_ts: self.start_ts,
            duration,
            byteps,
            pps,
            pkt_len_mean: len_mean,
            pkt_len_std: len_std,
            iat_mean,
            iat_std,
            fwd_pkts: self.packet_count,
            bwd_pkts: 0,
            fwd_seg_size: len_mean,
            bwd_seg_size: 0.0,
            label: self.has_malicious,
        }
    }
}

fn decode_proto(code: u16) -> u8 {
    if (code & (0xF0)) != 0 {
        6
    } else if (code & (1 << 8)) != 0 {
        17
    } else if (code & (1 << 2)) != 0 {
        1
    } else {
        0
    }
}
