use anyhow::{Context, Result, bail};
use ndarray::{Array1, Array2, Array3};
use ndarray_npy::NpzWriter;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

use crate::common::{FlowKey, RawPacket};

#[derive(Clone)]
struct ActiveFlow {
    first_ts_ns: i64,
    order: u64,
    packets: Vec<RawPacket>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WindowAgg {
    packet_count: u32,
    byte_count: u64,
    flow_keys: HashSet<FlowKey>,
    last_seen_ns: i64,
}

#[derive(Clone)]
struct WindowContribution {
    ts_ns: i64,
    byte_count: u64,
    flow_key: FlowKey,
}

#[derive(Clone, Default)]
struct IndexedWindowAgg {
    packet_count: u32,
    byte_count: u64,
    flow_key_counts: HashMap<FlowKey, u32>,
    last_seen_ns: i64,
    events: VecDeque<WindowContribution>,
}

impl IndexedWindowAgg {
    fn add_packet(&mut self, packet: &RawPacket) {
        let flow_key = packet_flow_key(packet);
        self.packet_count += 1;
        self.byte_count += packet.len as u64;
        *self.flow_key_counts.entry(flow_key.clone()).or_insert(0) += 1;
        self.last_seen_ns = self.last_seen_ns.max(packet.ts_ns);
        self.events.push_back(WindowContribution {
            ts_ns: packet.ts_ns,
            byte_count: packet.len as u64,
            flow_key,
        });
    }

    fn remove_packet(&mut self, packet: &RawPacket) {
        let Some(contribution) = self.events.pop_front() else {
            return;
        };
        debug_assert_eq!(contribution.ts_ns, packet.ts_ns);
        debug_assert_eq!(contribution.byte_count, packet.len as u64);

        self.packet_count = self.packet_count.saturating_sub(1);
        self.byte_count = self.byte_count.saturating_sub(contribution.byte_count);
        if let Some(count) = self.flow_key_counts.get_mut(&contribution.flow_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.flow_key_counts.remove(&contribution.flow_key);
            }
        }
        if contribution.ts_ns == self.last_seen_ns {
            self.last_seen_ns = self.events.iter().map(|event| event.ts_ns).max().unwrap_or(0);
        }
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn to_window_agg(&self, cutoff_timestamp_ns: i64) -> WindowAgg {
        if self.last_seen_ns <= cutoff_timestamp_ns {
            return WindowAgg {
                packet_count: self.packet_count,
                byte_count: self.byte_count,
                flow_keys: self.flow_key_counts.keys().cloned().collect(),
                last_seen_ns: self.last_seen_ns,
            };
        }

        let mut agg = WindowAgg::default();
        for contribution in &self.events {
            if contribution.ts_ns > cutoff_timestamp_ns {
                continue;
            }
            agg.packet_count += 1;
            agg.byte_count += contribution.byte_count;
            agg.flow_keys.insert(contribution.flow_key.clone());
            agg.last_seen_ns = agg.last_seen_ns.max(contribution.ts_ns);
        }
        agg
    }
}

struct SlidingWindow {
    window_duration_ns: i64,
    packet_limit: usize,
    events: VecDeque<RawPacket>,
    endpoint_index: HashMap<IpAddr, IndexedWindowAgg>,
    service_index: HashMap<(u8, u16), IndexedWindowAgg>,
    edge_index: HashMap<(IpAddr, IpAddr), IndexedWindowAgg>,
}

impl SlidingWindow {
    fn new(window_duration_s: u64, packet_limit: usize) -> Self {
        Self {
            window_duration_ns: (window_duration_s as i64) * 1_000_000_000,
            packet_limit,
            events: VecDeque::new(),
            endpoint_index: HashMap::new(),
            service_index: HashMap::new(),
            edge_index: HashMap::new(),
        }
    }

    fn update(&mut self, packet: RawPacket) {
        let ts = packet.ts_ns;
        self.add_to_indices(&packet);
        self.events.push_back(packet);
        while let Some(front) = self.events.front() {
            if front.ts_ns < ts - self.window_duration_ns || self.events.len() > self.packet_limit {
                if let Some(expired) = self.events.pop_front() {
                    self.remove_from_indices(&expired);
                }
            } else {
                break;
            }
        }
    }

    fn add_to_indices(&mut self, packet: &RawPacket) {
        self.endpoint_index.entry(packet.src_ip).or_default().add_packet(packet);
        if packet.dst_ip != packet.src_ip {
            self.endpoint_index.entry(packet.dst_ip).or_default().add_packet(packet);
        }

        self.service_index
            .entry((packet.protocol, packet.src_port))
            .or_default()
            .add_packet(packet);
        if packet.dst_port != packet.src_port {
            self.service_index
                .entry((packet.protocol, packet.dst_port))
                .or_default()
                .add_packet(packet);
        }

        self.edge_index
            .entry(canonical_edge_key(&packet.src_ip, &packet.dst_ip))
            .or_default()
            .add_packet(packet);
    }

    fn remove_from_indices(&mut self, packet: &RawPacket) {
        Self::remove_from_index(&mut self.endpoint_index, &packet.src_ip, packet);
        if packet.dst_ip != packet.src_ip {
            Self::remove_from_index(&mut self.endpoint_index, &packet.dst_ip, packet);
        }

        Self::remove_from_index(&mut self.service_index, &(packet.protocol, packet.src_port), packet);
        if packet.dst_port != packet.src_port {
            Self::remove_from_index(&mut self.service_index, &(packet.protocol, packet.dst_port), packet);
        }

        Self::remove_from_index(
            &mut self.edge_index,
            &canonical_edge_key(&packet.src_ip, &packet.dst_ip),
            packet,
        );
    }

    fn remove_from_index<K>(index: &mut HashMap<K, IndexedWindowAgg>, key: &K, packet: &RawPacket)
    where
        K: Clone + Eq + Hash,
    {
        let should_remove = if let Some(agg) = index.get_mut(key) {
            agg.remove_packet(packet);
            agg.is_empty()
        } else {
            false
        };
        if should_remove {
            index.remove(key);
        }
    }

    fn endpoint_state(&self, ip: &IpAddr, cutoff_timestamp_ns: i64) -> WindowAgg {
        self.endpoint_index
            .get(ip)
            .map(|agg| agg.to_window_agg(cutoff_timestamp_ns))
            .unwrap_or_default()
    }

    fn service_state(&self, port: u16, protocol: u8, cutoff_timestamp_ns: i64) -> WindowAgg {
        self.service_index
            .get(&(protocol, port))
            .map(|agg| agg.to_window_agg(cutoff_timestamp_ns))
            .unwrap_or_default()
    }

    fn edge_state(&self, src_ip: &IpAddr, dst_ip: &IpAddr, cutoff_timestamp_ns: i64) -> WindowAgg {
        self.edge_index
            .get(&canonical_edge_key(src_ip, dst_ip))
            .map(|agg| agg.to_window_agg(cutoff_timestamp_ns))
            .unwrap_or_default()
    }

    fn graph_tokens(&self, count: usize, cutoff_timestamp_ns: i64) -> Vec<[f32; 16]> {
        let mut edges: Vec<_> = self
            .edge_index
            .values()
            .map(|agg| agg.to_window_agg(cutoff_timestamp_ns))
            .filter(|agg| agg.packet_count > 0)
            .collect();
        edges.sort_by(|a, b| {
            (b.packet_count, b.byte_count, b.last_seen_ns).cmp(&(a.packet_count, a.byte_count, a.last_seen_ns))
        });

        let mut out = vec![[0.0f32; 16]; count];
        for (idx, agg) in edges.into_iter().take(count).enumerate() {
            out[idx][0] = (agg.packet_count as f32 + 1.0).ln();
            out[idx][1] = (agg.byte_count as f32 + 1.0).ln();
            out[idx][2] = (agg.flow_keys.len() as f32 + 1.0).ln();
            if agg.last_seen_ns > 0 {
                out[idx][3] = ((cutoff_timestamp_ns - agg.last_seen_ns).max(0) as f32 + 1.0).ln();
            }
        }
        out
    }

    #[cfg(test)]
    fn scan_endpoint_state(&self, ip: &IpAddr, cutoff_timestamp_ns: i64) -> WindowAgg {
        let mut agg = WindowAgg::default();
        for packet in &self.events {
            if packet.ts_ns > cutoff_timestamp_ns {
                continue;
            }
            if &packet.src_ip == ip || &packet.dst_ip == ip {
                agg.packet_count += 1;
                agg.byte_count += packet.len as u64;
                agg.flow_keys.insert(packet_flow_key(packet));
                agg.last_seen_ns = agg.last_seen_ns.max(packet.ts_ns);
            }
        }
        agg
    }

    #[cfg(test)]
    fn scan_service_state(&self, port: u16, protocol: u8, cutoff_timestamp_ns: i64) -> WindowAgg {
        let mut agg = WindowAgg::default();
        for packet in &self.events {
            if packet.ts_ns > cutoff_timestamp_ns {
                continue;
            }
            if packet.protocol == protocol && (packet.dst_port == port || packet.src_port == port) {
                agg.packet_count += 1;
                agg.byte_count += packet.len as u64;
                agg.flow_keys.insert(packet_flow_key(packet));
                agg.last_seen_ns = agg.last_seen_ns.max(packet.ts_ns);
            }
        }
        agg
    }

    #[cfg(test)]
    fn scan_edge_state(&self, src_ip: &IpAddr, dst_ip: &IpAddr, cutoff_timestamp_ns: i64) -> WindowAgg {
        let mut agg = WindowAgg::default();
        for packet in &self.events {
            if packet.ts_ns > cutoff_timestamp_ns {
                continue;
            }
            if canonical_edge_key(&packet.src_ip, &packet.dst_ip) == canonical_edge_key(src_ip, dst_ip) {
                agg.packet_count += 1;
                agg.byte_count += packet.len as u64;
                agg.flow_keys.insert(packet_flow_key(packet));
                agg.last_seen_ns = agg.last_seen_ns.max(packet.ts_ns);
            }
        }
        agg
    }

    #[cfg(test)]
    fn scan_graph_tokens(&self, count: usize, cutoff_timestamp_ns: i64) -> Vec<[f32; 16]> {
        let mut map: HashMap<(IpAddr, IpAddr), WindowAgg> = HashMap::new();
        for packet in &self.events {
            if packet.ts_ns > cutoff_timestamp_ns {
                continue;
            }
            let key = canonical_edge_key(&packet.src_ip, &packet.dst_ip);
            let agg = map.entry(key).or_default();
            agg.packet_count += 1;
            agg.byte_count += packet.len as u64;
            agg.flow_keys.insert(packet_flow_key(packet));
            agg.last_seen_ns = agg.last_seen_ns.max(packet.ts_ns);
        }

        let mut edges: Vec<_> = map.into_values().collect();
        edges.sort_by(|a, b| {
            (b.packet_count, b.byte_count, b.last_seen_ns).cmp(&(a.packet_count, a.byte_count, a.last_seen_ns))
        });

        let mut out = vec![[0.0f32; 16]; count];
        for (idx, agg) in edges.into_iter().take(count).enumerate() {
            out[idx][0] = (agg.packet_count as f32 + 1.0).ln();
            out[idx][1] = (agg.byte_count as f32 + 1.0).ln();
            out[idx][2] = (agg.flow_keys.len() as f32 + 1.0).ln();
            if agg.last_seen_ns > 0 {
                out[idx][3] = ((cutoff_timestamp_ns - agg.last_seen_ns).max(0) as f32 + 1.0).ln();
            }
        }
        out
    }

    #[cfg(test)]
    fn assert_index_matches_scan(&self, cutoff_timestamp_ns: i64) {
        for ip in self.endpoint_index.keys() {
            assert_eq!(
                self.endpoint_state(ip, cutoff_timestamp_ns),
                self.scan_endpoint_state(ip, cutoff_timestamp_ns)
            );
        }
        for (protocol, port) in self.service_index.keys() {
            assert_eq!(
                self.service_state(*port, *protocol, cutoff_timestamp_ns),
                self.scan_service_state(*port, *protocol, cutoff_timestamp_ns)
            );
        }
        for (src_ip, dst_ip) in self.edge_index.keys() {
            assert_eq!(
                self.edge_state(src_ip, dst_ip, cutoff_timestamp_ns),
                self.scan_edge_state(src_ip, dst_ip, cutoff_timestamp_ns)
            );
        }
        assert_eq!(
            self.graph_tokens(5, cutoff_timestamp_ns),
            self.scan_graph_tokens(5, cutoff_timestamp_ns)
        );
    }
}

#[derive(Serialize)]
struct SchemaMetadata {
    version: String,
    context_mode: String,
    packet_cutoff: usize,
    graph_token_count: usize,
    flow_timeout_s: u64,
    window_duration_s: u64,
    window_packet_limit: usize,
    timestamp_unit: String,
    timeout_policy: String,
    time_feature_transform: String,
    packet_code_encoding: String,
    derived_feature_set: String,
    dims: HashMap<String, usize>,
}

#[derive(Serialize)]
struct ShardMetadata {
    name: String,
    label_counts: HashMap<String, usize>,
}

#[derive(Serialize)]
struct Metadata {
    cache_schema_version: String,
    source_names: Vec<String>,
    source_mode: String,
    pretrain_data: Option<String>,
    total_packets: usize,
    normal_packets: usize,
    attack_packets: usize,
    event_count: usize,
    label_counts: HashMap<String, usize>,
    shards: Vec<ShardMetadata>,
    schema: SchemaMetadata,
    packet_cutoff: usize,
    graph_token_count: usize,
    dims: HashMap<String, usize>,
    normal_only: bool,
    max_events: Option<usize>,
    timestamp_unit: String,
    raw_timestamp_unit: String,
    raw_field7_mode: String,
    timeout_policy: String,
    time_feature_transform: String,
    packet_code_encoding: String,
    derived_feature_set: String,
    label_policy: String,
    segment_label_policy: String,
    metadata_fields: Vec<String>,
    sampling_unit: String,
    cache_builder: String,
    attack_flow_keys: usize,
    sampled_normal_flow_keys: usize,
    selected_flow_keys: usize,
}

struct EncodedFlow {
    packet_tokens: [[f32; 16]; 20],
    flow_tokens: [f32; 12],
    endpoint_tokens: [[f32; 12]; 2],
    service_tokens: [f32; 10],
    edge_tokens: [f32; 8],
    graph_tokens: [[f32; 16]; 5],
    packet_mask: [u8; 20],
    label: i32,
    segment_label: i32,
    flow_key_hash: u64,
    segment_id: i32,
    cutoff_timestamp_ns: i64,
    prefix_len: i16,
    protocol: i16,
    dst_port: i32,
    length_bucket: i16,
    service_bucket: u64,
}

struct ShardWriter {
    out_dir: String,
    shard_flows: usize,
    shard_index: usize,
    total_flows: usize,
    shard_metadata: Vec<ShardMetadata>,
    label_counts: HashMap<String, usize>,
    rows: Vec<EncodedFlow>,
}

impl ShardWriter {
    fn new(out_dir: &str, shard_flows: usize) -> Self {
        Self {
            out_dir: out_dir.to_string(),
            shard_flows,
            shard_index: 0,
            total_flows: 0,
            shard_metadata: Vec::new(),
            label_counts: HashMap::new(),
            rows: Vec::new(),
        }
    }

    fn add(&mut self, row: EncodedFlow) -> Result<()> {
        self.rows.push(row);
        if self.rows.len() >= self.shard_flows {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }

        let shard_name = format!("shard_{:05}.npz", self.shard_index);
        let shard_path = Path::new(&self.out_dir).join(&shard_name);
        let file = File::create(&shard_path)?;
        let mut npz = NpzWriter::new(file);
        let n = self.rows.len();

        let mut packet_tokens = Array3::<f32>::zeros((n, 20, 16));
        let mut flow_tokens = Array2::<f32>::zeros((n, 12));
        let mut endpoint_tokens = Array3::<f32>::zeros((n, 2, 12));
        let mut service_tokens = Array2::<f32>::zeros((n, 10));
        let mut edge_tokens = Array2::<f32>::zeros((n, 8));
        let mut graph_tokens = Array3::<f32>::zeros((n, 5, 16));
        let mut packet_masks = Array2::<u8>::zeros((n, 20));
        let mut labels = Array1::<i32>::zeros(n);
        let mut segment_labels = Array1::<i32>::zeros(n);
        let mut flow_key_hashes = Array1::<u64>::zeros(n);
        let mut segment_ids = Array1::<i32>::zeros(n);
        let mut cutoff_timestamp_ns = Array1::<i64>::zeros(n);
        let mut prefix_lens = Array1::<i16>::zeros(n);
        let mut protocols = Array1::<i16>::zeros(n);
        let mut dst_ports = Array1::<i32>::zeros(n);
        let mut length_buckets = Array1::<i16>::zeros(n);
        let mut service_buckets = Array1::<u64>::zeros(n);
        let mut shard_label_counts: HashMap<String, usize> = HashMap::new();

        for (i, row) in self.rows.iter().enumerate() {
            for j in 0..20 {
                for k in 0..16 {
                    packet_tokens[[i, j, k]] = row.packet_tokens[j][k];
                }
                packet_masks[[i, j]] = row.packet_mask[j];
            }
            for j in 0..12 {
                flow_tokens[[i, j]] = row.flow_tokens[j];
            }
            for a in 0..2 {
                for b in 0..12 {
                    endpoint_tokens[[i, a, b]] = row.endpoint_tokens[a][b];
                }
            }
            for j in 0..10 {
                service_tokens[[i, j]] = row.service_tokens[j];
            }
            for j in 0..8 {
                edge_tokens[[i, j]] = row.edge_tokens[j];
            }
            for a in 0..5 {
                for b in 0..16 {
                    graph_tokens[[i, a, b]] = row.graph_tokens[a][b];
                }
            }

            labels[i] = row.label;
            segment_labels[i] = row.segment_label;
            flow_key_hashes[i] = row.flow_key_hash;
            segment_ids[i] = row.segment_id;
            cutoff_timestamp_ns[i] = row.cutoff_timestamp_ns;
            prefix_lens[i] = row.prefix_len;
            protocols[i] = row.protocol;
            dst_ports[i] = row.dst_port;
            length_buckets[i] = row.length_bucket;
            service_buckets[i] = row.service_bucket;
            *shard_label_counts.entry(row.label.to_string()).or_insert(0) += 1;
            *self.label_counts.entry(row.label.to_string()).or_insert(0) += 1;
        }

        npz.add_array("packet_tokens", &packet_tokens)?;
        npz.add_array("flow_tokens", &flow_tokens)?;
        npz.add_array("endpoint_tokens", &endpoint_tokens)?;
        npz.add_array("service_tokens", &service_tokens)?;
        npz.add_array("edge_tokens", &edge_tokens)?;
        npz.add_array("graph_tokens", &graph_tokens)?;
        npz.add_array("packet_masks", &packet_masks)?;
        npz.add_array("labels", &labels)?;
        npz.add_array("segment_labels", &segment_labels)?;
        npz.add_array("flow_key_hashes", &flow_key_hashes)?;
        npz.add_array("segment_ids", &segment_ids)?;
        npz.add_array("cutoff_timestamp_ns", &cutoff_timestamp_ns)?;
        npz.add_array("prefix_lens", &prefix_lens)?;
        npz.add_array("protocols", &protocols)?;
        npz.add_array("dst_ports", &dst_ports)?;
        npz.add_array("length_buckets", &length_buckets)?;
        npz.add_array("service_buckets", &service_buckets)?;
        npz.finish()?;

        self.shard_metadata.push(ShardMetadata {
            name: shard_name,
            label_counts: shard_label_counts,
        });
        self.total_flows += n;
        self.shard_index += 1;
        self.rows.clear();
        Ok(())
    }
}

fn packet_flow_key(packet: &RawPacket) -> FlowKey {
    FlowKey::new(
        packet.src_ip,
        packet.dst_ip,
        packet.src_port,
        packet.dst_port,
        packet.protocol,
    )
    .canonical()
}

fn canonical_edge_key(src_ip: &IpAddr, dst_ip: &IpAddr) -> (IpAddr, IpAddr) {
    if src_ip <= dst_ip {
        (*src_ip, *dst_ip)
    } else {
        (*dst_ip, *src_ip)
    }
}

fn service_port_from_flow_key(fkey: &FlowKey) -> u16 {
    let ports = [fkey.src_port, fkey.dst_port];
    let mut candidates: Vec<u16> = ports.into_iter().filter(|port| *port > 0).collect();
    if candidates.is_empty() {
        return 0;
    }
    candidates.sort_unstable();
    if let Some(port) = candidates.iter().copied().find(|port| *port <= 1023) {
        return port;
    }
    if let Some(port) = candidates.iter().copied().find(|port| *port <= 49151) {
        return port;
    }
    candidates[0]
}

fn parse_data_line(line: &str, label: bool, timestamp_unit: &str, field7_mode: &str) -> Option<RawPacket> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let ip_version: u8 = fields.first()?.parse().ok()?;
    let timestamp_value: i64 = fields.get(5)?.parse().ok()?;
    let ts_ns = match timestamp_unit {
        "ns" => timestamp_value,
        "us" => timestamp_value * 1000,
        _ => return None,
    };

    let (protocol, packet_code, len) = match fields.len() {
        8 => {
            let field7: u16 = fields[6].parse().ok()?;
            let (protocol, packet_code) = resolve_8_column_protocol_and_code(ip_version, field7, field7_mode)?;
            (protocol, packet_code, fields[7].parse().ok()?)
        },
        9 => (
            fields[6].parse().ok()?,
            fields[7].parse().ok()?,
            fields[8].parse().ok()?,
        ),
        _ => return None,
    };

    Some(RawPacket {
        src_ip: fields[1].parse().ok()?,
        dst_ip: fields[2].parse().ok()?,
        src_port: fields[3].parse().ok()?,
        dst_port: fields[4].parse().ok()?,
        ts_ns,
        protocol,
        packet_code,
        len,
        label,
    })
}

fn resolve_8_column_protocol_and_code(ip_version: u8, field7: u16, field7_mode: &str) -> Option<(u8, u16)> {
    match field7_mode {
        "protocol" => {
            let protocol = field7 as u8;
            Some((protocol, packet_code_from_protocol(ip_version, protocol)))
        },
        "packet_code" => Some((decode_protocol_from_packet_code(field7), field7)),
        "auto" => {
            if matches!(field7, 0 | 1 | 2 | 6 | 17 | 58) {
                let protocol = field7 as u8;
                Some((protocol, packet_code_from_protocol(ip_version, protocol)))
            } else {
                Some((decode_protocol_from_packet_code(field7), field7))
            }
        },
        _ => None,
    }
}

fn packet_code_from_protocol(ip_version: u8, protocol: u8) -> u16 {
    let mut code = match ip_version {
        4 => 1 << 0,
        6 => 1 << 1,
        _ => 0,
    };
    match protocol {
        17 => code |= 1 << 8,
        1 => code |= 1 << 2,
        2 => code |= 1 << 3,
        0 | 6 => {},
        _ => code |= 1 << 9,
    }
    code
}

fn decode_protocol_from_packet_code(packet_code: u16) -> u8 {
    if packet_code & ((1 << 4) | (1 << 5) | (1 << 6) | (1 << 7)) != 0 {
        6
    } else if packet_code & (1 << 8) != 0 {
        17
    } else if packet_code & (1 << 2) != 0 {
        1
    } else if packet_code & (1 << 3) != 0 {
        2
    } else {
        0
    }
}

fn read_labels(label_path: &str) -> Result<Vec<bool>> {
    let text = fs::read_to_string(label_path).with_context(|| format!("Failed to read label file: {label_path}"))?;
    Ok(text
        .chars()
        .filter_map(|ch| match ch {
            '0' => Some(false),
            '1' => Some(true),
            _ if ch.is_whitespace() => None,
            _ => None,
        })
        .collect())
}

fn packet_code_bit(packet_code: u16, bit: u8) -> f32 {
    if packet_code & (1u16 << bit) != 0 { 1.0 } else { 0.0 }
}

fn safe_ratio(numerator: f32, denominator: f32) -> f32 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

fn port_group(port: u16) -> f32 {
    if port == 0 {
        0.0
    } else if port <= 1023 {
        1.0 / 3.0
    } else if port <= 49151 {
        2.0 / 3.0
    } else {
        1.0
    }
}

fn protocol_group(protocol: u8) -> f32 {
    match protocol {
        6 => 1.0 / 4.0,
        17 => 2.0 / 4.0,
        1 | 58 => 3.0 / 4.0,
        _ => 1.0,
    }
}

fn flow_hash(source_name: &str, fkey: &FlowKey) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    source_name.hash(&mut hasher);
    fkey.hash(&mut hasher);
    hasher.finish()
}

fn service_bucket(protocol: u8, dst_port: u16) -> u64 {
    ((protocol as u64) << 16) | dst_port as u64
}

#[allow(clippy::too_many_arguments)]
fn encode_flow(
    source_name: &str,
    fkey: &FlowKey,
    packets: &[RawPacket],
    packet_cutoff: usize,
    graph_token_count: usize,
    sliding_window: &SlidingWindow,
    segment_id: i32,
    attack_flow_keys: &HashSet<FlowKey>,
    label_policy: &str,
) -> EncodedFlow {
    let real_packets = &packets[..packets.len().min(packet_cutoff)];
    let cutoff_timestamp_ns = real_packets.last().map(|p| p.ts_ns).unwrap_or(0);

    let mut packet_tokens = [[0.0f32; 16]; 20];
    let mut packet_mask = [0u8; 20];
    let mut previous_real_packet: Option<&RawPacket> = None;

    for (idx, packet) in real_packets.iter().enumerate() {
        packet_mask[idx] = 1;
        packet_tokens[idx][0] = packet.protocol as f32 / 255.0;
        packet_tokens[idx][1] = (packet.len as f32 + 1.0).ln();
        packet_tokens[idx][2] = packet.src_port as f32 / 65535.0;
        packet_tokens[idx][3] = packet.dst_port as f32 / 65535.0;
        let iat = if let Some(prev) = previous_real_packet {
            (packet.ts_ns - prev.ts_ns).max(0) as f32
        } else {
            0.0
        };
        packet_tokens[idx][4] = (iat + 1.0).ln();
        packet_tokens[idx][5] = if packet.src_ip == fkey.src_ip { 0.0 } else { 1.0 };
        for bit in 0..10 {
            packet_tokens[idx][6 + bit as usize] = packet_code_bit(packet.packet_code, bit);
        }
        previous_real_packet = Some(packet);
    }

    let mut flow_token = [0.0f32; 12];
    let mut total_bytes = 0u64;
    if !real_packets.is_empty() {
        let protocol_mean = real_packets.iter().map(|p| p.protocol as f32).sum::<f32>() / real_packets.len() as f32;
        total_bytes = real_packets.iter().map(|p| p.len as u64).sum();
        let duration_ns = (real_packets.last().unwrap().ts_ns - real_packets[0].ts_ns).max(0) as f32;
        let n = real_packets.len() as f32;
        flow_token[0] = protocol_mean / 255.0;
        flow_token[1] = (total_bytes as f32 + 1.0).ln();
        flow_token[2] = (n + 1.0).ln();
        flow_token[3] = (duration_ns + 1.0).ln();
        flow_token[4] = fkey.src_port as f32 / 65535.0;
        flow_token[5] = fkey.dst_port as f32 / 65535.0;
        flow_token[6] = real_packets
            .iter()
            .map(|p| packet_code_bit(p.packet_code, 4))
            .sum::<f32>()
            / n;
        flow_token[7] = real_packets
            .iter()
            .map(|p| packet_code_bit(p.packet_code, 5))
            .sum::<f32>()
            / n;
        flow_token[8] = real_packets
            .iter()
            .map(|p| packet_code_bit(p.packet_code, 6).max(packet_code_bit(p.packet_code, 7)))
            .sum::<f32>()
            / n;

        if real_packets.len() > 1 {
            let mut iats = Vec::with_capacity(real_packets.len() - 1);
            let mut direction_changes = 0usize;
            for pair in real_packets.windows(2) {
                iats.push((pair[1].ts_ns - pair[0].ts_ns).max(0) as f32);
                let prev_dir = pair[0].src_ip != fkey.src_ip;
                let curr_dir = pair[1].src_ip != fkey.src_ip;
                if prev_dir != curr_dir {
                    direction_changes += 1;
                }
            }
            let iat_mean = iats.iter().sum::<f32>() / iats.len() as f32;
            let iat_var = iats
                .iter()
                .map(|iat| {
                    let delta = iat - iat_mean;
                    delta * delta
                })
                .sum::<f32>()
                / iats.len() as f32;
            flow_token[9] = (iat_mean + 1.0).ln();
            flow_token[10] = ((iat_var.sqrt() / (iat_mean + 1.0)) + 1.0).ln();
            flow_token[11] = direction_changes as f32 / (real_packets.len() - 1) as f32;
        }
    }

    let src_endpoint = sliding_window.endpoint_state(&fkey.src_ip, cutoff_timestamp_ns);
    let dst_endpoint = sliding_window.endpoint_state(&fkey.dst_ip, cutoff_timestamp_ns);
    let mut endpoint_tokens = [[0.0f32; 12]; 2];
    for (idx, state) in [src_endpoint, dst_endpoint].iter().enumerate() {
        endpoint_tokens[idx][0] = (state.packet_count as f32 + 1.0).ln();
        endpoint_tokens[idx][1] = (state.byte_count as f32 + 1.0).ln();
        endpoint_tokens[idx][2] = (state.flow_keys.len() as f32 + 1.0).ln();
        if state.last_seen_ns > 0 {
            endpoint_tokens[idx][3] = ((cutoff_timestamp_ns - state.last_seen_ns).max(0) as f32 + 1.0).ln();
        }
        endpoint_tokens[idx][4] = (safe_ratio(state.byte_count as f32, state.packet_count as f32) + 1.0).ln();
        endpoint_tokens[idx][5] = (safe_ratio(state.packet_count as f32, state.flow_keys.len() as f32) + 1.0).ln();
    }

    let service_port = service_port_from_flow_key(fkey);
    let service_state = sliding_window.service_state(service_port, fkey.protocol, cutoff_timestamp_ns);
    let mut service_token = [0.0f32; 10];
    service_token[0] = (service_state.packet_count as f32 + 1.0).ln();
    service_token[1] = (service_state.byte_count as f32 + 1.0).ln();
    service_token[2] = (service_state.flow_keys.len() as f32 + 1.0).ln();
    if service_state.last_seen_ns > 0 {
        service_token[3] = ((cutoff_timestamp_ns - service_state.last_seen_ns).max(0) as f32 + 1.0).ln();
    }
    service_token[4] = (safe_ratio(service_state.byte_count as f32, service_state.packet_count as f32) + 1.0).ln();
    service_token[5] = (safe_ratio(service_state.packet_count as f32, service_state.flow_keys.len() as f32) + 1.0).ln();
    service_token[6] = safe_ratio(service_state.flow_keys.len() as f32, service_state.packet_count as f32);
    service_token[7] = port_group(service_port);
    service_token[8] = protocol_group(fkey.protocol);

    let edge_state = sliding_window.edge_state(&fkey.src_ip, &fkey.dst_ip, cutoff_timestamp_ns);
    let mut edge_token = [0.0f32; 8];
    edge_token[0] = (edge_state.packet_count as f32 + 1.0).ln();
    edge_token[1] = (edge_state.byte_count as f32 + 1.0).ln();
    edge_token[2] = (edge_state.flow_keys.len() as f32 + 1.0).ln();
    if edge_state.last_seen_ns > 0 {
        edge_token[3] = ((cutoff_timestamp_ns - edge_state.last_seen_ns).max(0) as f32 + 1.0).ln();
    }
    edge_token[4] = (safe_ratio(edge_state.byte_count as f32, edge_state.packet_count as f32) + 1.0).ln();
    edge_token[5] = (safe_ratio(edge_state.packet_count as f32, edge_state.flow_keys.len() as f32) + 1.0).ln();
    edge_token[6] = safe_ratio(real_packets.len() as f32, edge_state.packet_count as f32);
    edge_token[7] = if real_packets.iter().any(|packet| packet.src_ip != fkey.src_ip) {
        1.0
    } else {
        0.0
    };

    let graph_vec = sliding_window.graph_tokens(graph_token_count, cutoff_timestamp_ns);
    let mut graph_tokens = [[0.0f32; 16]; 5];
    for (idx, row) in graph_vec.into_iter().enumerate().take(5) {
        graph_tokens[idx] = row;
    }

    let segment_label = if real_packets.iter().any(|packet| packet.label) {
        1
    } else {
        0
    };
    let label = match label_policy {
        "segment_only" => segment_label,
        _ => {
            if segment_label == 1 || attack_flow_keys.contains(fkey) {
                1
            } else {
                0
            }
        },
    };
    let length_bucket = (total_bytes.max(1) as f64).log2().floor().min(16.0) as i16;

    EncodedFlow {
        packet_tokens,
        flow_tokens: flow_token,
        endpoint_tokens,
        service_tokens: service_token,
        edge_tokens: edge_token,
        graph_tokens,
        packet_mask,
        label,
        segment_label,
        flow_key_hash: flow_hash(source_name, fkey),
        segment_id,
        cutoff_timestamp_ns,
        prefix_len: real_packets.len() as i16,
        protocol: fkey.protocol as i16,
        dst_port: service_port as i32,
        length_bucket,
        service_bucket: service_bucket(fkey.protocol, service_port),
    }
}

fn scan_selected_flow_keys(
    data_path: &str,
    label_path: &str,
    timestamp_unit: &str,
    field7_mode: &str,
    max_packets: usize,
    attack_centered: bool,
    normal_flow_sample_size: usize,
    seed: u64,
) -> Result<(
    HashSet<FlowKey>,
    HashSet<FlowKey>,
    HashSet<FlowKey>,
    usize,
    usize,
    usize,
)> {
    let labels = read_labels(label_path)?;
    let file = File::open(data_path).with_context(|| format!("Failed to open data file: {data_path}"))?;
    let reader = BufReader::new(file);
    let mut attack_keys = HashSet::new();
    let mut normal_sample = Vec::<FlowKey>::new();
    let mut normal_sample_set = HashSet::<FlowKey>::new();
    let mut normal_seen = 0usize;
    let mut total = 0usize;
    let mut normal = 0usize;
    let mut attack = 0usize;
    let mut rng = StdRng::seed_from_u64(seed);

    for (row_idx, line) in reader.lines().enumerate() {
        if max_packets > 0 && total >= max_packets {
            break;
        }
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Some(label) = labels.get(row_idx).copied() else {
            break;
        };
        let Some(packet) = parse_data_line(&line, label, timestamp_unit, field7_mode) else {
            continue;
        };
        total += 1;
        let fkey = packet_flow_key(&packet);
        if packet.label {
            attack += 1;
            attack_keys.insert(fkey);
            continue;
        }

        normal += 1;
        if !attack_centered {
            continue;
        }
        if normal_sample_set.contains(&fkey) {
            continue;
        }
        normal_seen += 1;
        if normal_sample.len() < normal_flow_sample_size {
            normal_sample.push(fkey.clone());
            normal_sample_set.insert(fkey);
            continue;
        }
        let replace_idx = rng.gen_range(0..normal_seen);
        if replace_idx < normal_flow_sample_size {
            normal_sample_set.remove(&normal_sample[replace_idx]);
            normal_sample[replace_idx] = fkey.clone();
            normal_sample_set.insert(fkey);
        }
    }

    let normal_keys: HashSet<FlowKey> = normal_sample.into_iter().collect();
    let mut selected_keys = attack_keys.clone();
    if attack_centered {
        selected_keys.extend(normal_keys.iter().cloned());
    }
    Ok((selected_keys, attack_keys, normal_keys, total, normal, attack))
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    data_path: &str,
    label_path: &str,
    out_dir: &str,
    source_name: &str,
    packet_cutoff: usize,
    flow_timeout_s: u64,
    window_duration_s: u64,
    window_packet_limit: usize,
    shard_flows: usize,
    max_packets: usize,
    timeout_check_interval: usize,
    graph_token_count: usize,
    timestamp_unit: &str,
    field7_mode: &str,
    attack_centered: bool,
    label_policy: &str,
    normal_flow_sample_size: usize,
    seed: u64,
) -> Result<()> {
    if packet_cutoff != 20 {
        bail!("Rust finetune-cache currently supports packet_cutoff=20 only");
    }
    if graph_token_count != 5 {
        bail!("Rust finetune-cache currently supports graph_token_count=5 only");
    }
    if !matches!(label_policy, "flow_contaminated" | "segment_only") {
        bail!("Unsupported label_policy: {label_policy}");
    }

    if Path::new(out_dir).exists() {
        fs::remove_dir_all(out_dir)?;
    }
    fs::create_dir_all(out_dir)?;

    let (selected_flow_keys, attack_flow_keys, normal_flow_keys, _scan_total, _scan_normal, _scan_attack) =
        scan_selected_flow_keys(
            data_path,
            label_path,
            timestamp_unit,
            field7_mode,
            max_packets,
            attack_centered,
            normal_flow_sample_size,
            seed,
        )?;

    log::info!(
        "finetune-cache {}: attack_flow_keys={} sampled_normal_flow_keys={} selected_flow_keys={}",
        source_name,
        attack_flow_keys.len(),
        normal_flow_keys.len(),
        selected_flow_keys.len()
    );

    let labels = read_labels(label_path)?;
    let file = File::open(data_path).with_context(|| format!("Failed to open data file: {data_path}"))?;
    let reader = BufReader::new(file);
    let mut sliding_window = SlidingWindow::new(window_duration_s, window_packet_limit);
    let mut active_flows: HashMap<FlowKey, ActiveFlow> = HashMap::new();
    let mut segment_counters: HashMap<FlowKey, i32> = HashMap::new();
    let mut next_flow_order = 0u64;
    let mut writer = ShardWriter::new(out_dir, shard_flows);
    let flow_timeout_ns = (flow_timeout_s as i64) * 1_000_000_000;
    let mut emitted_packets = 0usize;
    let mut total_packets = 0usize;
    let mut normal_packets = 0usize;
    let mut attack_packets = 0usize;

    for (row_idx, line) in reader.lines().enumerate() {
        if max_packets > 0 && emitted_packets >= max_packets {
            break;
        }
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Some(label) = labels.get(row_idx).copied() else {
            break;
        };
        let Some(packet) = parse_data_line(&line, label, timestamp_unit, field7_mode) else {
            continue;
        };

        emitted_packets += 1;
        total_packets += 1;
        if packet.label {
            attack_packets += 1;
        } else {
            normal_packets += 1;
        }

        if emitted_packets % timeout_check_interval == 0 {
            let mut timeout_keys: Vec<_> = active_flows
                .iter()
                .filter_map(|(key, flow)| {
                    if packet.ts_ns - flow.first_ts_ns >= flow_timeout_ns {
                        Some((key.clone(), flow.order))
                    } else {
                        None
                    }
                })
                .collect();
            timeout_keys.sort_by_key(|(_, order)| *order);
            for (key, _) in timeout_keys {
                if let Some(flow) = active_flows.remove(&key) {
                    let segment_id = *segment_counters.get(&key).unwrap_or(&0);
                    let encoded = encode_flow(
                        source_name,
                        &key,
                        &flow.packets,
                        packet_cutoff,
                        graph_token_count,
                        &sliding_window,
                        segment_id,
                        &attack_flow_keys,
                        label_policy,
                    );
                    writer.add(encoded)?;
                    segment_counters.insert(key, segment_id + 1);
                }
            }
        }

        sliding_window.update(packet.clone());

        let key = packet_flow_key(&packet);
        if attack_centered && !selected_flow_keys.contains(&key) {
            continue;
        }

        let flow = active_flows.entry(key.clone()).or_insert_with(|| {
            let order = next_flow_order;
            next_flow_order += 1;
            ActiveFlow {
                first_ts_ns: packet.ts_ns,
                order,
                packets: Vec::new(),
            }
        });
        flow.packets.push(packet);

        if flow.packets.len() >= packet_cutoff {
            let flow = active_flows.remove(&key).unwrap();
            let segment_id = *segment_counters.get(&key).unwrap_or(&0);
            let encoded = encode_flow(
                source_name,
                &key,
                &flow.packets,
                packet_cutoff,
                graph_token_count,
                &sliding_window,
                segment_id,
                &attack_flow_keys,
                label_policy,
            );
            writer.add(encoded)?;
            segment_counters.insert(key, segment_id + 1);
        }

        if emitted_packets % 100000 == 0 {
            log::info!(
                "packets={} events={} shards={}",
                emitted_packets,
                writer.total_flows + writer.rows.len(),
                writer.shard_index
            );
        }
    }

    let mut remaining: Vec<_> = active_flows.into_iter().collect();
    remaining.sort_by_key(|(_, flow)| flow.order);
    for (key, flow) in remaining {
        let segment_id = *segment_counters.get(&key).unwrap_or(&0);
        let encoded = encode_flow(
            source_name,
            &key,
            &flow.packets,
            packet_cutoff,
            graph_token_count,
            &sliding_window,
            segment_id,
            &attack_flow_keys,
            label_policy,
        );
        writer.add(encoded)?;
        segment_counters.insert(key, segment_id + 1);
    }

    writer.flush()?;

    let mut dims = HashMap::new();
    dims.insert("packet_tokens".to_string(), 16);
    dims.insert("flow_token".to_string(), 12);
    dims.insert("endpoint_token".to_string(), 12);
    dims.insert("service_token".to_string(), 10);
    dims.insert("edge_token".to_string(), 8);
    dims.insert("graph_token".to_string(), 16);

    let schema = SchemaMetadata {
        version: "flow_v2.0".to_string(),
        context_mode: "mixed_causal_context".to_string(),
        packet_cutoff,
        graph_token_count,
        flow_timeout_s,
        window_duration_s,
        window_packet_limit,
        timestamp_unit: "ns".to_string(),
        timeout_policy: "segment_max_age".to_string(),
        time_feature_transform: "log1p_delta_ns".to_string(),
        packet_code_encoding: "pcap_processor_bits_v1".to_string(),
        derived_feature_set: "flow_v2_derived.2".to_string(),
        dims: dims.clone(),
    };
    let metadata = Metadata {
        cache_schema_version: "flow_v2_cache.2".to_string(),
        source_names: vec![source_name.to_string()],
        source_mode: "data_label_pairs".to_string(),
        pretrain_data: None,
        total_packets,
        normal_packets,
        attack_packets,
        event_count: writer.total_flows,
        label_counts: writer.label_counts,
        shards: writer.shard_metadata,
        schema,
        packet_cutoff,
        graph_token_count,
        dims,
        normal_only: false,
        max_events: None,
        timestamp_unit: "ns".to_string(),
        raw_timestamp_unit: timestamp_unit.to_string(),
        raw_field7_mode: field7_mode.to_string(),
        timeout_policy: "segment_max_age".to_string(),
        time_feature_transform: "log1p_delta_ns".to_string(),
        packet_code_encoding: "pcap_processor_bits_v1".to_string(),
        derived_feature_set: "flow_v2_derived.2".to_string(),
        label_policy: label_policy.to_string(),
        segment_label_policy: "segment_max".to_string(),
        metadata_fields: vec![
            "flow_key_hashes".to_string(),
            "segment_ids".to_string(),
            "cutoff_timestamp_ns".to_string(),
            "segment_labels".to_string(),
            "prefix_lens".to_string(),
            "protocols".to_string(),
            "dst_ports".to_string(),
            "length_buckets".to_string(),
            "service_buckets".to_string(),
        ],
        sampling_unit: "detection_event_segment".to_string(),
        cache_builder: "rust_pcap_processor_finetune_cache".to_string(),
        attack_flow_keys: attack_flow_keys.len(),
        sampled_normal_flow_keys: normal_flow_keys.len(),
        selected_flow_keys: selected_flow_keys.len(),
    };
    let metadata_text = serde_json::to_string_pretty(&metadata)?;
    fs::write(Path::new(out_dir).join("metadata.json"), &metadata_text)?;
    fs::write(Path::new(out_dir).join("meta.json"), metadata_text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
    }

    #[allow(clippy::too_many_arguments)]
    fn packet(src: u8, dst: u8, src_port: u16, dst_port: u16, protocol: u8, ts_ns: i64, len: u16) -> RawPacket {
        RawPacket {
            src_ip: ip(src),
            dst_ip: ip(dst),
            src_port,
            dst_port,
            protocol,
            packet_code: 0,
            ts_ns,
            len,
            label: false,
        }
    }

    fn assert_agg_eq(actual: WindowAgg, expected: WindowAgg) {
        assert_eq!(actual.packet_count, expected.packet_count);
        assert_eq!(actual.byte_count, expected.byte_count);
        assert_eq!(actual.flow_keys, expected.flow_keys);
        assert_eq!(actual.last_seen_ns, expected.last_seen_ns);
    }

    #[test]
    fn indexed_endpoint_service_and_edge_match_scan_with_cutoff() {
        let mut window = SlidingWindow::new(300, 100);
        window.update(packet(1, 2, 1234, 80, 6, 100, 40));
        window.update(packet(1, 3, 1234, 80, 6, 200, 50));
        window.update(packet(4, 2, 53, 5353, 17, 300, 60));
        window.update(packet(1, 2, 1234, 80, 6, 400, 70));

        window.assert_index_matches_scan(250);
        window.assert_index_matches_scan(400);

        assert_agg_eq(
            window.endpoint_state(&ip(1), 250),
            window.scan_endpoint_state(&ip(1), 250),
        );
        assert_agg_eq(window.service_state(80, 6, 400), window.scan_service_state(80, 6, 400));
        assert_agg_eq(
            window.edge_state(&ip(1), &ip(2), 400),
            window.scan_edge_state(&ip(1), &ip(2), 400),
        );
    }

    #[test]
    fn indexed_window_removes_duplicate_flow_keys_only_after_last_packet_expires() {
        let mut window = SlidingWindow::new(300, 2);
        window.update(packet(1, 2, 1234, 80, 6, 100, 40));
        window.update(packet(1, 2, 1234, 80, 6, 200, 50));
        window.update(packet(3, 4, 5555, 22, 6, 300, 60));

        window.assert_index_matches_scan(300);
        let endpoint = window.endpoint_state(&ip(1), 300);
        assert_eq!(endpoint.packet_count, 1);
        assert_eq!(endpoint.byte_count, 50);
        assert_eq!(endpoint.flow_keys.len(), 1);
    }

    #[test]
    fn indexed_window_expires_by_time_and_keeps_graph_tokens_consistent() {
        let mut window = SlidingWindow::new(1, 100);
        window.update(packet(1, 2, 1111, 80, 6, 0, 40));
        window.update(packet(3, 4, 2222, 443, 6, 500_000_000, 60));
        window.update(packet(1, 2, 1111, 80, 6, 2_000_000_000, 70));

        window.assert_index_matches_scan(2_000_000_000);
        assert_eq!(window.endpoint_state(&ip(3), 2_000_000_000).packet_count, 0);
        assert_eq!(
            window.graph_tokens(5, 2_000_000_000),
            window.scan_graph_tokens(5, 2_000_000_000)
        );
    }
}
