use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use log::{info, warn};
use pcap::{Capture, Linktype, Packet, Savefile};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::common::Rule;

// =============================================================================
// 1. 协议编码定义
// =============================================================================

const PKT_TYPE_IPV4: u8 = 0;
const PKT_TYPE_IPV6: u8 = 1;
const PKT_TYPE_ICMP: u8 = 2;
const PKT_TYPE_IGMP: u8 = 3;
const PKT_TYPE_TCP_SYN: u8 = 4;
const PKT_TYPE_TCP_ACK: u8 = 5;
const PKT_TYPE_TCP_FIN: u8 = 6;
const PKT_TYPE_TCP_RST: u8 = 7;
const PKT_TYPE_UDP: u8 = 8;
const PKT_TYPE_UNKNOWN: u8 = 9;

fn to_pkt_code(t: u8) -> u16 {
    1 << t
}

fn set_pkt_code(code: &mut u16, t: u8) {
    *code |= to_pkt_code(t);
}

// =============================================================================
// 2. 结构化包信息
// =============================================================================
#[derive(Debug)]
pub struct PacketMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_code: u16,
    pub ip_len: u16,
    pub ts_ns: i64,
}

// =============================================================================
// 3. 解析逻辑
// =============================================================================
pub fn parse_packet(packet: &Packet, link_type: Linktype) -> Option<PacketMeta> {
    let data = packet.data;
    let offset;
    let eth_type;

    // --- L2: Ethernet / SLL 解析 ---
    if link_type == Linktype::ETHERNET {
        if data.len() < 14 {
            return None;
        }
        eth_type = u16::from_be_bytes([data[12], data[13]]);
        offset = 14;
    } else if link_type == Linktype(113) {
        // Linux Cooked (SLL)
        if data.len() < 16 {
            return None;
        }
        eth_type = u16::from_be_bytes([data[14], data[15]]);
        offset = 16;
    } else {
        return None;
    }

    // 初始化变量
    let mut packet_code: u16 = 0;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let packet_length: u16;
    let src_ip: IpAddr;
    let dst_ip: IpAddr;

    // 用于指向 L4 协议类型的变量
    let next_proto: u8;
    let l4_offset: usize;

    // --- L3: IP 解析 (设置 IPv4/IPv6 Code) ---
    match eth_type {
        0x0800 => {
            // IPv4
            if data.len() < offset + 20 {
                return None;
            }

            set_pkt_code(&mut packet_code, PKT_TYPE_IPV4);
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
            // IPv6
            if data.len() < offset + 40 {
                return None;
            }

            set_pkt_code(&mut packet_code, PKT_TYPE_IPV6);
            let payload_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            packet_length = payload_len + 40; // IPv6 header is 40 bytes

            next_proto = data[offset + 6];

            let mut s_arr = [0u8; 16];
            s_arr.copy_from_slice(&data[offset + 8..offset + 24]);
            let mut d_arr = [0u8; 16];
            d_arr.copy_from_slice(&data[offset + 24..offset + 40]);

            src_ip = IpAddr::V6(Ipv6Addr::from(s_arr));
            dst_ip = IpAddr::V6(Ipv6Addr::from(d_arr));

            l4_offset = offset + 40;
        },
        _ => return None, // basic_packet_bad
    };

    // --- L4: Transport Layer 解析 (TCP/UDP/ICMP/IGMP) ---
    if data.len() > l4_offset {
        match next_proto {
            6 => {
                // TCP
                if data.len() >= l4_offset + 20 {
                    src_port = u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
                    dst_port = u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);

                    let flags = data[l4_offset + 13];
                    if (flags & 0x02) != 0 {
                        set_pkt_code(&mut packet_code, PKT_TYPE_TCP_SYN);
                    } // SYN
                    if (flags & 0x01) != 0 {
                        set_pkt_code(&mut packet_code, PKT_TYPE_TCP_FIN);
                    } // FIN
                    if (flags & 0x04) != 0 {
                        set_pkt_code(&mut packet_code, PKT_TYPE_TCP_RST);
                    } // RST
                    if (flags & 0x10) != 0 {
                        set_pkt_code(&mut packet_code, PKT_TYPE_TCP_ACK);
                    } // ACK
                } else {
                    return None;
                }
            },
            17 => {
                // UDP
                if data.len() >= l4_offset + 8 {
                    src_port = u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
                    dst_port = u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);

                    set_pkt_code(&mut packet_code, PKT_TYPE_UDP);
                } else {
                    return None;
                }
            },
            1 => {
                // ICMP
                set_pkt_code(&mut packet_code, PKT_TYPE_ICMP);
            },
            2 => {
                // IGMP
                set_pkt_code(&mut packet_code, PKT_TYPE_IGMP);
            },
            58 => {
                set_pkt_code(&mut packet_code, PKT_TYPE_UNKNOWN);
            },
            _ => {
                set_pkt_code(&mut packet_code, PKT_TYPE_UNKNOWN);
            },
        }
    } else {
        set_pkt_code(&mut packet_code, PKT_TYPE_UNKNOWN);
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

// =============================================================================
// 4. 全局 Filter (Step 1)
// =============================================================================
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

    // 自动检测 Linktype
    let first_file = &files[0];
    let cap_test = Capture::from_file(first_file).context("Failed to open first pcap")?;
    let global_linktype = cap_test.get_datalink();
    info!("🔗 Detected Linktype: {:?} from {:?}", global_linktype, first_file);

    let dead_cap = Capture::dead(global_linktype)?;

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
            if let Some(meta) = parse_packet(&packet, link_type) {
                let ts_f64 = meta.ts_ns as f64 / 1e9;
                let mut target_type = "BENIGN";

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

                let writer = if let Some(w) = writers.get_mut(target_type) {
                    w
                } else {
                    let out_path = Path::new(output_dir).join(format!("{}.pcap", target_type));
                    let path_str = out_path.to_string_lossy().to_string();
                    generated_paths.insert(target_type.to_string(), path_str.clone());
                    writers.insert(target_type.to_string(), dead_cap.savefile(path_str)?);
                    writers.get_mut(target_type).unwrap()
                };
                writer.write(&packet);
            }
            count += 1;
            if count % 5_000_000 == 0 {
                info!("   Processed {} packets...", count);
            }
        }
    }

    for (_, w) in writers.iter_mut() {
        w.flush()?;
    }
    Ok(generated_paths)
}

// =============================================================================
// 5. 解析并生成 .data / .label (Step 3) - 输出格式调整
// =============================================================================
pub fn process_and_write(pcap_path: &str, output_prefix: &str, rules: &Vec<Rule>) -> Result<()> {
    let index = build_ip_index(rules)?;
    let mut data_w = BufWriter::new(File::create(format!("{}.data", output_prefix))?);
    let mut label_w = BufWriter::new(File::create(format!("{}.label", output_prefix))?);

    let mut cap = Capture::from_file(pcap_path)?;
    let link_type = cap.get_datalink();
    info!("   Parsing mixed pcap with Linktype: {:?}", link_type);

    let mut align_time: i64 = -1;
    let mut count = 0;

    while let Ok(packet) = cap.next_packet() {
        if let Some(meta) = parse_packet(&packet, link_type) {
            if align_time == -1 {
                align_time = meta.ts_ns;
            }
            let ts_f64 = meta.ts_ns as f64 / 1e9;

            let is_src_atk = index
                .get(&meta.src_ip)
                .map_or(false, |rs| rs.iter().any(|(s, e, _)| ts_f64 >= *s && ts_f64 <= *e));
            let is_dst_atk = index
                .get(&meta.dst_ip)
                .map_or(false, |rs| rs.iter().any(|(s, e, _)| ts_f64 >= *s && ts_f64 <= *e));

            let label = if is_src_atk || is_dst_atk { b"1" } else { b"0" };
            let rel_ts = meta.ts_ns - align_time;

            writeln!(
                data_w,
                "{} {} {} {} {} {} {} {}",
                if meta.src_ip.is_ipv4() { 4 } else { 6 }, // 1. Version
                meta.src_ip,                               // 2. Src IP
                meta.dst_ip,                               // 3. Dst IP
                meta.src_port,                             // 4. Src Port
                meta.dst_port,                             // 5. Dst Port
                rel_ts,                                    // 6. Relative Time (ns)
                meta.packet_code,                          // 7. Packet Code (Protocol + Flags Mask)
                meta.ip_len                                // 8. Length
            )?;

            label_w.write_all(label)?;
            count += 1;
        }
    }
    data_w.flush()?;
    label_w.flush()?;

    if count == 0 {
        warn!("⚠️ Generated dataset is empty!");
    } else {
        info!("   ✅ Generated {} entries.", count);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::BufReader;
    use std::path::Path;

    #[test]
    fn test_verify_dataset_generation_from_json() {
        // ================= 配置区域 =================
        // 1. 设置文件路径
        let pcap_path = "./data/experiments/unsw/17-2/Analysis_mixed.pcap";
        let config_path = "config/unsw/attacks_2015-02-18.json";

        // 2. 指定你要验证的场景名称 (必须与 JSON 中的 "name" 和 PCAP 文件名对应)
        let target_scenario_name = "Analysis";

        // 3. 测试输出位置
        let output_dir = "./test_output";
        let output_prefix = format!("{}/test_verify_real", output_dir);
        // ===========================================

        println!("🧪 Starting verification test (Real Config)...");
        println!("   📂 Input PCAP:   {}", pcap_path);
        println!("   📜 Config File:  {}", config_path);
        println!("   🎯 Target Scenario: {}", target_scenario_name);

        // --- 步骤 A: 检查文件存在性 ---
        if !Path::new(pcap_path).exists() {
            panic!(
                "❌ Test failed: PCAP file not found at {}. Please check path.",
                pcap_path
            );
        }
        if !Path::new(config_path).exists() {
            panic!(
                "❌ Test failed: Config file not found at {}. Please check path.",
                config_path
            );
        }

        // --- 步骤 B: 从 JSON 读取并提取规则 ---
        let file = File::open(config_path).expect("Failed to open config file");
        let reader = BufReader::new(file);
        let json: serde_json::Value = serde_json::from_reader(reader).expect("Failed to parse JSON");

        let mut target_rules: Vec<Rule> = Vec::new();
        let mut found_scenario = false;

        // 遍历 JSON 中的 attacks 数组寻找目标场景
        if let Some(attacks) = json.get("attacks").and_then(|a| a.as_array()) {
            for attack in attacks {
                if let Some(name) = attack.get("name").and_then(|n| n.as_str()) {
                    if name == target_scenario_name {
                        found_scenario = true;
                        if let Some(rules_json) = attack.get("rules") {
                            // 将 JSON 数组反序列化为 Vec<crate::Rule>
                            target_rules = serde_json::from_value(rules_json.clone())
                                .expect("Failed to deserialize rules for scenario");
                            println!("   ✅ Loaded {} rules for scenario '{}'", target_rules.len(), name);
                        }
                        break; // 找到了就退出循环
                    }
                }
            }
        }

        if !found_scenario {
            panic!("❌ Scenario '{}' not found in config file!", target_scenario_name);
        }
        if target_rules.is_empty() {
            println!("⚠️ Warning: The target scenario has NO rules. .data will likely be all 0 labels.");
        }

        // --- 步骤 C: 执行处理 ---
        if !Path::new(output_dir).exists() {
            fs::create_dir_all(output_dir).expect("Failed to create test output dir");
        }

        let result = process_and_write(pcap_path, &output_prefix, &target_rules);
        assert!(
            result.is_ok(),
            "❌ process_and_write returned error: {:?}",
            result.err()
        );

        // --- 步骤 D: 验证结果 ---
        let data_path = format!("{}.data", output_prefix);
        let label_path = format!("{}.label", output_prefix);

        let data_meta = fs::metadata(&data_path).expect("❌ .data file missing");
        let label_meta = fs::metadata(&label_path).expect("❌ .label file missing");

        println!("------------------------------------------------");
        println!("📊 Result Statistics:");
        println!("   Data File Size:  {} bytes", data_meta.len());
        println!("   Label File Size: {} bytes", label_meta.len());
        println!("------------------------------------------------");

        assert!(data_meta.len() > 0, "❌ FAILURE: .data file is empty! Parsing failed.");
        assert!(label_meta.len() > 0, "❌ FAILURE: .label file is empty!");

        let label_content = fs::read(&label_path).unwrap();
        let attack_count = label_content.iter().filter(|&&b| b == b'1').count();
        println!(
            "🔎 Found {} attack packets (Label '1') in generated dataset.",
            attack_count
        );

        if attack_count == 0 {
            println!("⚠️ Note: No attack packets were identified. Check if timestamps/IPs in JSON match the PCAP.");
        } else {
            println!("🎉 SUCCESS: Identified {} malicious packets!", attack_count);
        }
    }
}
