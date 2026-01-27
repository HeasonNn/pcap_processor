mod common;
mod export;
mod flow;
mod merger;
mod parser;

use crate::common::{Args, Config};
use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

fn ensure_dir(path: &str) -> std::io::Result<()> {
    let p = Path::new(path);
    if !p.exists() {
        std::fs::create_dir_all(p)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let args = Args::parse();

    // 1. 加载配置与预检
    let config_path = Path::new(&args.config);
    if !config_path.exists() {
        anyhow::bail!("Config file not found: {}", args.config);
    }
    let file = File::open(config_path).context("Failed to open config file")?;
    let reader = BufReader::new(file);
    let config: Config = serde_json::from_reader(reader).context("Failed to parse config JSON")?;

    let workspace = &config.global.workspace_dir;
    let raw_pcap = &config.global.raw_pcap;
    let sampling_rate = config.global.benign_sampling_rate;

    ensure_dir(workspace)?;
    if !Path::new(raw_pcap).exists() {
        anyhow::bail!("Raw PCAP source does not exist: {}", raw_pcap);
    }

    // 收集所有规则
    let mut all_rules = Vec::new();
    for attack in &config.attacks {
        all_rules.extend(attack.rules.clone());
    }

    info!("🚀 Pipeline started. Workspace: {}", workspace);
    info!("🎲 Benign Sampling Rate: {:.2}%", sampling_rate * 100.0);

    // Step 1: Filter (分离流量)
    info!("Step 1: Filtering Raw PCAP...");
    let generated_files = parser::filter_malicious_pkt(raw_pcap, &all_rules, workspace)?;

    let benign_pcap_path = Path::new(workspace).join("BENIGN.pcap");
    if !benign_pcap_path.exists() {
        warn!("⚠️ BENIGN.pcap was not created. Merging might fail if background traffic is required.");
    }

    // Step 2, 3 & 4: Loop Scenarios
    for (idx, attack) in config.attacks.iter().enumerate() {
        info!("------------------------------------------------");
        info!(">>> [{}/{}] Scenario: {}", idx + 1, config.attacks.len(), attack.name);

        if attack.rules.is_empty() {
            warn!("   Skipping scenario '{}' (No rules defined)", attack.name);
            continue;
        }

        let attack_type = &attack.rules[0].attack_type;
        let attack_fragment_path: PathBuf = match generated_files.get(attack_type) {
            Some(path) => PathBuf::from(path),
            None => {
                let fallback = Path::new(workspace).join(format!("{}.pcap", attack_type));
                if fallback.exists() {
                    fallback
                } else {
                    warn!("❌ Attack file for type '{}' not found. Skipping.", attack_type);
                    continue;
                }
            },
        };

        let mixed_pcap_path = Path::new(workspace).join(format!("{}_mixed.pcap", attack.name));
        let dataset_prefix = Path::new(workspace).join(&attack.name);

        // Step 2: Merge
        info!(
            "   Merge: {} + BENIGN (Sampled) -> {}",
            attack_type,
            mixed_pcap_path.display()
        );
        let atk_str = attack_fragment_path.to_str().unwrap();
        let ben_str = benign_pcap_path.to_str().unwrap();
        let mix_str = mixed_pcap_path.to_str().unwrap();

        match merger::merge_pcap(atk_str, ben_str, mix_str, sampling_rate) {
            Ok(count) => {
                info!("   ✅ Merge success. Total packets: {}", count);

                // Step 3: Parse & Label (生成 .data 和 .label)
                info!("   Labeling: Generating dataset...");
                let prefix_str = dataset_prefix.to_str().unwrap();
                let data_file = format!("{}.data", prefix_str);
                let label_file = format!("{}.label", prefix_str);

                if let Err(e) = parser::process_and_write(mix_str, prefix_str, &attack.rules) {
                    error!("   ❌ Parse/Label failed: {}\nCaused by: {:?}", e, e.source());
                } else {
                    info!("   ✅ Dataset generated: .data / .label");

                    // Step 4: Flow Construction (生成 .csv)
                    let csv_path = format!("{}.csv", prefix_str);
                    info!("   Flow: Constructing flows -> {}", csv_path);

                    let engine = flow::FlowEngine::new(5_000_000);
                    match engine.run(&data_file, &label_file, &csv_path) {
                        Ok(_) => info!("   ✅ Flow CSV generated: {}", attack.name),
                        Err(e) => error!("   ❌ Flow Construction failed: {}", e),
                    }
                }
            },
            Err(e) => error!("   ❌ Replay/Merge failed: {}", e),
        }
    }

    info!("🎉 Pipeline completed successfully.");
    Ok(())
}
