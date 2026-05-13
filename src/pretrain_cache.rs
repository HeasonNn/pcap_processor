use anyhow::{Context, Result, bail};
use ndarray::{Array2, Array3};
use ndarray_npy::NpzWriter;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

use crate::common::{FlowKey, RawPacket};

#[derive(Clone)]
struct ActiveFlow {
    first_ts_us: i64,
    packets: Vec<RawPacket>,
}

#[derive(Clone, Default)]
struct EndpointAgg {
    packet_count: u32,
    byte_count: u64,
    flow_keys: HashSet<FlowKey>,
    last_seen_us: i64,
}

#[derive(Clone, Default)]
struct ServiceAgg {
    packet_count: u32,
    byte_count: u64,
    flow_keys: HashSet<FlowKey>,
    last_seen_us: i64,
}

#[derive(Clone, Default)]
struct EdgeAgg {
    packet_count: u32,
    byte_count: u64,
    flow_keys: HashSet<FlowKey>,
    last_seen_us: i64,
}

struct SlidingWindow {
    window_duration_us: i64,
    packet_limit: usize,
    events: VecDeque<RawPacket>,
}

impl SlidingWindow {
    fn new(window_duration_s: u64, packet_limit: usize) -> Self {
        Self {
            window_duration_us: (window_duration_s as i64) * 1_000_000,
            packet_limit,
            events: VecDeque::new(),
        }
    }

    fn update(&mut self, packet: RawPacket) {
        let ts = packet.ts_ns / 1000;
        self.events.push_back(packet);
        while let Some(front) = self.events.front() {
            let front_us = front.ts_ns / 1000;
            if front_us < ts - self.window_duration_us || self.events.len() > self.packet_limit {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    fn endpoint_state(&self, ip: &IpAddr, cutoff_timestamp_us: i64) -> EndpointAgg {
        let mut agg = EndpointAgg::default();
        for packet in &self.events {
            let ts = packet.ts_ns / 1000;
            if ts > cutoff_timestamp_us {
                continue;
            }
            if &packet.src_ip == ip || &packet.dst_ip == ip {
                agg.packet_count += 1;
                agg.byte_count += packet.len as u64;
                agg.flow_keys.insert(FlowKey::new(
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                ));
                agg.last_seen_us = agg.last_seen_us.max(ts);
            }
        }
        agg
    }

    fn service_state(&self, port: u16, protocol: u8, cutoff_timestamp_us: i64) -> ServiceAgg {
        let mut agg = ServiceAgg::default();
        for packet in &self.events {
            let ts = packet.ts_ns / 1000;
            if ts > cutoff_timestamp_us {
                continue;
            }
            if packet.dst_port == port && packet.protocol == protocol {
                agg.packet_count += 1;
                agg.byte_count += packet.len as u64;
                agg.flow_keys.insert(FlowKey::new(
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                ));
                agg.last_seen_us = agg.last_seen_us.max(ts);
            }
        }
        agg
    }

    fn edge_state(&self, src_ip: &IpAddr, dst_ip: &IpAddr, cutoff_timestamp_us: i64) -> EdgeAgg {
        let mut agg = EdgeAgg::default();
        for packet in &self.events {
            let ts = packet.ts_ns / 1000;
            if ts > cutoff_timestamp_us {
                continue;
            }
            if &packet.src_ip == src_ip && &packet.dst_ip == dst_ip {
                agg.packet_count += 1;
                agg.byte_count += packet.len as u64;
                agg.flow_keys.insert(FlowKey::new(
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                ));
                agg.last_seen_us = agg.last_seen_us.max(ts);
            }
        }
        agg
    }

    fn graph_tokens(&self, count: usize, cutoff_timestamp_us: i64) -> Vec<[f32; 16]> {
        let mut map: HashMap<(IpAddr, IpAddr), EdgeAgg> = HashMap::new();
        for packet in &self.events {
            let ts = packet.ts_ns / 1000;
            if ts > cutoff_timestamp_us {
                continue;
            }
            let key = (packet.src_ip, packet.dst_ip);
            let agg = map.entry(key).or_default();
            agg.packet_count += 1;
            agg.byte_count += packet.len as u64;
            agg.flow_keys.insert(FlowKey::new(
                packet.src_ip,
                packet.dst_ip,
                packet.src_port,
                packet.dst_port,
                packet.protocol,
            ));
            agg.last_seen_us = agg.last_seen_us.max(ts);
        }

        let mut edges: Vec<_> = map.into_values().collect();
        edges.sort_by(|a, b| {
            (b.packet_count, b.byte_count, b.last_seen_us).cmp(&(a.packet_count, a.byte_count, a.last_seen_us))
        });

        let mut out = vec![[0.0f32; 16]; count];
        for (idx, agg) in edges.into_iter().take(count).enumerate() {
            out[idx][0] = (agg.packet_count as f32 + 1.0).ln();
            out[idx][1] = (agg.byte_count as f32 + 1.0).ln();
            out[idx][2] = (agg.flow_keys.len() as f32 + 1.0).ln();
            if agg.last_seen_us > 0 {
                out[idx][3] = ((cutoff_timestamp_us - agg.last_seen_us).max(0) as f32 + 1.0).ln();
            }
        }
        out
    }
}

#[derive(Serialize)]
struct Metadata {
    data_path: String,
    shards: Vec<String>,
    total_flows: usize,
    packet_cutoff: usize,
    graph_token_count: usize,
}

struct ShardWriter {
    out_dir: String,
    shard_flows: usize,
    shard_index: usize,
    total_flows: usize,
    shard_names: Vec<String>,
    packet_tokens: Vec<[[f32; 16]; 20]>,
    flow_tokens: Vec<[f32; 12]>,
    endpoint_tokens: Vec<[[f32; 12]; 2]>,
    service_tokens: Vec<[f32; 10]>,
    edge_tokens: Vec<[f32; 8]>,
    graph_tokens: Vec<[[f32; 16]; 5]>,
    packet_masks: Vec<[u8; 20]>,
}

impl ShardWriter {
    fn new(out_dir: &str, shard_flows: usize) -> Self {
        Self {
            out_dir: out_dir.to_string(),
            shard_flows,
            shard_index: 0,
            total_flows: 0,
            shard_names: Vec::new(),
            packet_tokens: Vec::new(),
            flow_tokens: Vec::new(),
            endpoint_tokens: Vec::new(),
            service_tokens: Vec::new(),
            edge_tokens: Vec::new(),
            graph_tokens: Vec::new(),
            packet_masks: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        packet_tokens: [[f32; 16]; 20],
        flow_tokens: [f32; 12],
        endpoint_tokens: [[f32; 12]; 2],
        service_tokens: [f32; 10],
        edge_tokens: [f32; 8],
        graph_tokens: [[f32; 16]; 5],
        packet_mask: [u8; 20],
    ) -> Result<()> {
        self.packet_tokens.push(packet_tokens);
        self.flow_tokens.push(flow_tokens);
        self.endpoint_tokens.push(endpoint_tokens);
        self.service_tokens.push(service_tokens);
        self.edge_tokens.push(edge_tokens);
        self.graph_tokens.push(graph_tokens);
        self.packet_masks.push(packet_mask);
        if self.packet_tokens.len() >= self.shard_flows {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.packet_tokens.is_empty() {
            return Ok(());
        }

        let shard_name = format!("shard_{:06}.npz", self.shard_index);
        let shard_path = Path::new(&self.out_dir).join(&shard_name);
        let file = File::create(&shard_path)?;
        let mut npz = NpzWriter::new(file);
        let n = self.packet_tokens.len();

        let mut packet_tokens = Array3::<f32>::zeros((n, 20, 16));
        let mut flow_tokens = Array2::<f32>::zeros((n, 12));
        let mut endpoint_tokens = Array3::<f32>::zeros((n, 2, 12));
        let mut service_tokens = Array2::<f32>::zeros((n, 10));
        let mut edge_tokens = Array2::<f32>::zeros((n, 8));
        let mut graph_tokens = Array3::<f32>::zeros((n, 5, 16));
        let mut packet_masks = Array2::<u8>::zeros((n, 20));

        for i in 0..n {
            for j in 0..20 {
                for k in 0..16 {
                    packet_tokens[[i, j, k]] = self.packet_tokens[i][j][k];
                }
                packet_masks[[i, j]] = self.packet_masks[i][j];
            }
            for j in 0..12 {
                flow_tokens[[i, j]] = self.flow_tokens[i][j];
            }
            for a in 0..2 {
                for b in 0..12 {
                    endpoint_tokens[[i, a, b]] = self.endpoint_tokens[i][a][b];
                }
            }
            for j in 0..10 {
                service_tokens[[i, j]] = self.service_tokens[i][j];
            }
            for j in 0..8 {
                edge_tokens[[i, j]] = self.edge_tokens[i][j];
            }
            for a in 0..5 {
                for b in 0..16 {
                    graph_tokens[[i, a, b]] = self.graph_tokens[i][a][b];
                }
            }
        }

        npz.add_array("packet_tokens", &packet_tokens)?;
        npz.add_array("flow_tokens", &flow_tokens)?;
        npz.add_array("endpoint_tokens", &endpoint_tokens)?;
        npz.add_array("service_tokens", &service_tokens)?;
        npz.add_array("edge_tokens", &edge_tokens)?;
        npz.add_array("graph_tokens", &graph_tokens)?;
        npz.add_array("packet_masks", &packet_masks)?;
        npz.finish()?;

        self.shard_names.push(shard_name);
        self.total_flows += n;
        self.shard_index += 1;
        self.packet_tokens.clear();
        self.flow_tokens.clear();
        self.endpoint_tokens.clear();
        self.service_tokens.clear();
        self.edge_tokens.clear();
        self.graph_tokens.clear();
        self.packet_masks.clear();
        Ok(())
    }
}

fn parse_data_line(line: &str) -> Option<RawPacket> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() != 9 {
        return None;
    }
    Some(RawPacket {
        src_ip: fields[1].parse().ok()?,
        dst_ip: fields[2].parse().ok()?,
        src_port: fields[3].parse().ok()?,
        dst_port: fields[4].parse().ok()?,
        ts_ns: fields[5].parse().ok()?,
        protocol: fields[6].parse().ok()?,
        packet_code: fields[7].parse().ok()?,
        len: fields[8].parse().ok()?,
        label: false,
    })
}

#[allow(clippy::type_complexity)]
fn encode_flow(
    fkey: &FlowKey,
    packets: &[RawPacket],
    packet_cutoff: usize,
    graph_token_count: usize,
    sliding_window: &SlidingWindow,
) -> (
    [[f32; 16]; 20],
    [f32; 12],
    [[f32; 12]; 2],
    [f32; 10],
    [f32; 8],
    [[f32; 16]; 5],
    [u8; 20],
) {
    let real_packets = &packets[..packets.len().min(packet_cutoff)];
    let cutoff_timestamp_us = real_packets.last().map(|p| p.ts_ns / 1000).unwrap_or(0);

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
            ((packet.ts_ns - prev.ts_ns) / 1000).max(0) as f32
        } else {
            0.0
        };
        packet_tokens[idx][4] = (iat + 1.0).ln();
        packet_tokens[idx][5] = if packet.src_ip == fkey.src_ip { 0.0 } else { 1.0 };
        packet_tokens[idx][6] = packet.packet_code as f32 / 1024.0;
        previous_real_packet = Some(packet);
    }

    let mut flow_token = [0.0f32; 12];
    if !real_packets.is_empty() {
        let protocol_mean = real_packets.iter().map(|p| p.protocol as f32).sum::<f32>() / real_packets.len() as f32;
        let total_bytes: u64 = real_packets.iter().map(|p| p.len as u64).sum();
        let duration_us = ((real_packets.last().unwrap().ts_ns - real_packets[0].ts_ns) / 1000).max(0) as f32;
        flow_token[0] = protocol_mean / 255.0;
        flow_token[1] = (total_bytes as f32 + 1.0).ln();
        flow_token[2] = (real_packets.len() as f32 + 1.0).ln();
        flow_token[3] = (duration_us + 1.0).ln();
        flow_token[4] = fkey.src_port as f32 / 65535.0;
        flow_token[5] = fkey.dst_port as f32 / 65535.0;
    }

    let src_endpoint = sliding_window.endpoint_state(&fkey.src_ip, cutoff_timestamp_us);
    let dst_endpoint = sliding_window.endpoint_state(&fkey.dst_ip, cutoff_timestamp_us);
    let mut endpoint_tokens = [[0.0f32; 12]; 2];
    for (idx, state) in [src_endpoint, dst_endpoint].iter().enumerate() {
        endpoint_tokens[idx][0] = (state.packet_count as f32 + 1.0).ln();
        endpoint_tokens[idx][1] = (state.byte_count as f32 + 1.0).ln();
        endpoint_tokens[idx][2] = (state.flow_keys.len() as f32 + 1.0).ln();
        if state.last_seen_us > 0 {
            endpoint_tokens[idx][3] = ((cutoff_timestamp_us - state.last_seen_us).max(0) as f32 + 1.0).ln();
        }
    }

    let service_state = sliding_window.service_state(fkey.dst_port, fkey.protocol, cutoff_timestamp_us);
    let mut service_token = [0.0f32; 10];
    service_token[0] = (service_state.packet_count as f32 + 1.0).ln();
    service_token[1] = (service_state.byte_count as f32 + 1.0).ln();
    service_token[2] = (service_state.flow_keys.len() as f32 + 1.0).ln();
    if service_state.last_seen_us > 0 {
        service_token[3] = ((cutoff_timestamp_us - service_state.last_seen_us).max(0) as f32 + 1.0).ln();
    }

    let edge_state = sliding_window.edge_state(&fkey.src_ip, &fkey.dst_ip, cutoff_timestamp_us);
    let mut edge_token = [0.0f32; 8];
    edge_token[0] = (edge_state.packet_count as f32 + 1.0).ln();
    edge_token[1] = (edge_state.byte_count as f32 + 1.0).ln();
    edge_token[2] = (edge_state.flow_keys.len() as f32 + 1.0).ln();
    if edge_state.last_seen_us > 0 {
        edge_token[3] = ((cutoff_timestamp_us - edge_state.last_seen_us).max(0) as f32 + 1.0).ln();
    }

    let graph_vec = sliding_window.graph_tokens(graph_token_count, cutoff_timestamp_us);
    let mut graph_tokens = [[0.0f32; 16]; 5];
    for (idx, row) in graph_vec.into_iter().enumerate().take(5) {
        graph_tokens[idx] = row;
    }

    (
        packet_tokens,
        flow_token,
        endpoint_tokens,
        service_token,
        edge_token,
        graph_tokens,
        packet_mask,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    data_path: &str,
    out_dir: &str,
    packet_cutoff: usize,
    flow_timeout_s: u64,
    window_duration_s: u64,
    window_packet_limit: usize,
    shard_flows: usize,
    max_flows: usize,
    timeout_check_interval: usize,
    graph_token_count: usize,
) -> Result<()> {
    if packet_cutoff != 20 {
        bail!("Rust pretrain-cache currently supports packet_cutoff=20 only");
    }
    if graph_token_count != 5 {
        bail!("Rust pretrain-cache currently supports graph_token_count=5 only");
    }

    fs::create_dir_all(out_dir)?;
    let file = File::open(data_path).with_context(|| format!("Failed to open data file: {data_path}"))?;
    let reader = BufReader::new(file);

    let mut sliding_window = SlidingWindow::new(window_duration_s, window_packet_limit);
    let mut active_flows: HashMap<FlowKey, ActiveFlow> = HashMap::new();
    let mut writer = ShardWriter::new(out_dir, shard_flows);
    let flow_timeout_us = (flow_timeout_s as i64) * 1_000_000;
    let mut packet_count = 0usize;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let packet = match parse_data_line(&line) {
            Some(packet) => packet,
            None => continue,
        };

        let packet_ts_us = packet.ts_ns / 1000;
        if packet_count % timeout_check_interval == 0 {
            let timeout_keys: Vec<_> = active_flows
                .iter()
                .filter_map(|(key, flow)| {
                    if packet_ts_us - flow.first_ts_us >= flow_timeout_us {
                        Some(key.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for key in timeout_keys {
                if let Some(flow) = active_flows.remove(&key) {
                    let encoded = encode_flow(&key, &flow.packets, packet_cutoff, graph_token_count, &sliding_window);
                    writer.add(
                        encoded.0, encoded.1, encoded.2, encoded.3, encoded.4, encoded.5, encoded.6,
                    )?;
                    if max_flows > 0 && writer.total_flows + writer.packet_tokens.len() >= max_flows {
                        break;
                    }
                }
            }
            if max_flows > 0 && writer.total_flows + writer.packet_tokens.len() >= max_flows {
                break;
            }
        }

        sliding_window.update(packet.clone());
        let key = FlowKey::new(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
        );
        let flow = active_flows.entry(key.clone()).or_insert_with(|| ActiveFlow {
            first_ts_us: packet_ts_us,
            packets: Vec::new(),
        });
        flow.packets.push(packet);

        if flow.packets.len() >= packet_cutoff {
            let flow = active_flows.remove(&key).unwrap();
            let encoded = encode_flow(&key, &flow.packets, packet_cutoff, graph_token_count, &sliding_window);
            writer.add(
                encoded.0, encoded.1, encoded.2, encoded.3, encoded.4, encoded.5, encoded.6,
            )?;
            if max_flows > 0 && writer.total_flows + writer.packet_tokens.len() >= max_flows {
                break;
            }
        }

        packet_count += 1;
        if packet_count % 100000 == 0 {
            log::info!(
                "packets={} flows={} shards={}",
                packet_count,
                writer.total_flows + writer.packet_tokens.len(),
                writer.shard_index
            );
        }
    }

    if max_flows == 0 || writer.total_flows + writer.packet_tokens.len() < max_flows {
        let remaining: Vec<_> = active_flows.into_iter().collect();
        for (key, flow) in remaining {
            let encoded = encode_flow(&key, &flow.packets, packet_cutoff, graph_token_count, &sliding_window);
            writer.add(
                encoded.0, encoded.1, encoded.2, encoded.3, encoded.4, encoded.5, encoded.6,
            )?;
            if max_flows > 0 && writer.total_flows + writer.packet_tokens.len() >= max_flows {
                break;
            }
        }
    }

    writer.flush()?;
    let metadata = Metadata {
        data_path: data_path.to_string(),
        shards: writer.shard_names,
        total_flows: writer.total_flows,
        packet_cutoff,
        graph_token_count,
    };
    let metadata_path = Path::new(out_dir).join("metadata.json");
    serde_json::to_writer_pretty(File::create(metadata_path)?, &metadata)?;
    Ok(())
}
