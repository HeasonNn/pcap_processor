mod common;
mod export;
mod flow;
mod merger;
mod parser;

use crate::common::{Args, Config};
use crate::parser::compact_pcap;
use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

fn ensure_dir<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    let p = path.as_ref();
    if !p.exists() {
        std::fs::create_dir_all(p)?;
    }
    Ok(())
}

fn run_one_scenario(
    workspace_dir: impl AsRef<Path>,
    scenario_name: &str,
    pos_pcap_path: impl AsRef<Path>,
    neg_pcap_path: impl AsRef<Path>,
    sampling_rate: f64,
    write_mixed_pcap: bool,
) -> Result<()> {
    let dataset_prefix_path = workspace_dir.as_ref().join(scenario_name);
    let prefix_str = dataset_prefix_path.to_string_lossy().to_string();
    let mixed_pcap_path = format!("{}_mixed.pcap", prefix_str);

    let pos_pcap_str = pos_pcap_path.as_ref().to_string_lossy().to_string();
    let neg_pcap_str = neg_pcap_path.as_ref().to_string_lossy().to_string();

    info!("Merge+Export: {} + NEG (Sampled) -> {}", pos_pcap_str, mixed_pcap_path);

    match merger::merge_pcap(
        &pos_pcap_str,
        &neg_pcap_str,
        &prefix_str,
        sampling_rate,
        write_mixed_pcap,
    ) {
        Ok(count) => {
            info!("✅ Merge+Export success. Total packets: {}", count);

            let data_file = format!("{}.data", prefix_str);
            let label_file = format!("{}.label", prefix_str);
            let csv_path = format!("{}.csv", prefix_str);
            info!("Flow: Constructing flows -> {}", csv_path);

            let engine = flow::FlowEngine::new(5_000_000);
            match engine.run(&data_file, &label_file, &csv_path) {
                Ok(_) => info!("✅ Flow CSV generated: {}", scenario_name),
                Err(e) => error!("❌ Flow Construction failed: {}", e),
            }
        },
        Err(e) => error!("❌ Merge+Export failed: {}", e),
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let args = Args::parse();

    // 1. Load config
    let config_path = Path::new(&args.config);
    if !config_path.exists() {
        anyhow::bail!("Config file not found: {}", args.config);
    }
    let file = File::open(config_path).context("Failed to open config file")?;
    let reader = BufReader::new(file);
    let config: Config = serde_json::from_reader(reader).context("Failed to parse config JSON")?;

    let workspace_str = &config.global.output_dir;
    let workspace_dir = Path::new(workspace_str);
    let mode = &config.global.mode;
    let sampling_rate = config.global.neg_sampling_rate;
    let write_mixed_pcap = config.global.write_mixed_pcap.unwrap_or(true);

    ensure_dir(workspace_dir)?;

    if mode == "rules" {
        let raw_pcap = config
            .global
            .raw_pcap
            .as_ref()
            .context("raw_pcap is required in rules mode")?;
        if !Path::new(raw_pcap).exists() {
            anyhow::bail!("Raw PCAP source does not exist: {}", raw_pcap);
        }

        // Collect all rules
        let mut all_rules = Vec::new();
        for s in &config.attacks {
            all_rules.extend(s.rules.clone());
        }

        info!("🚀 Pipeline started. Workspace: {}", workspace_str);
        info!("🎲 NEG Sampling Rate: {:.2}%", sampling_rate * 100.0);

        // Step 1: Filter (split)
        info!("Step 1: Filtering Raw PCAP...");
        let generated_files = parser::filter_malicious_pkt(raw_pcap, &all_rules, workspace_str)?;

        let neg_pcap_path = workspace_dir.join("BENIGN.pcap");
        if !neg_pcap_path.exists() {
            warn!("⚠️ BENIGN.pcap was not created. Merging might fail if background traffic is required.");
        }

        // Step 2/3/4: per-scenario
        for (idx, attack) in config.attacks.iter().enumerate() {
            info!("------------------------------------------------");
            info!(">>> [{}/{}] Scenario: {}", idx + 1, config.attacks.len(), attack.name);

            if attack.rules.is_empty() {
                warn!("Skipping scenario '{}' (No rules defined)", attack.name);
                continue;
            }

            let attack_type = &attack.rules[0].attack_type;
            let pos_fragment_path: PathBuf = match generated_files.get(attack_type) {
                Some(path) => PathBuf::from(path),
                None => {
                    let fallback = workspace_dir.join(format!("{}.pcap", attack_type));
                    if fallback.exists() {
                        fallback
                    } else {
                        warn!("❌ POS file for type '{}' not found. Skipping.", attack_type);
                        continue;
                    }
                },
            };

            run_one_scenario(
                workspace_dir,
                &attack.name,
                &pos_fragment_path,
                &neg_pcap_path,
                sampling_rate,
                write_mixed_pcap,
            )?;
        }

        info!("🎉 Pipeline completed successfully.");
        Ok(())
    } else if mode == "folder" {
        let pos_input_str = config
            .global
            .pos_glob
            .as_ref()
            .context("pos_glob is required in folder mode")?;
        let neg_glob = config
            .global
            .neg_glob
            .as_ref()
            .context("neg_glob is required in folder mode")?;

        // Collect POS inputs.
        // Supported layouts:
        //   (A) pos_dir/*.pcap
        //   (B) pos_dir/<scenario_dir>/*.pcap
        let pos_input_path = Path::new(pos_input_str);
        let mut pos_files: Vec<PathBuf> = Vec::new();
        if pos_input_path.is_dir() {
            for entry in std::fs::read_dir(pos_input_path)? {
                let entry = entry?;
                let p = entry.path();
                let ft = entry.file_type()?;

                if ft.is_file() {
                    if p.extension().and_then(|s| s.to_str()) == Some("pcap") {
                        pos_files.push(p);
                    }
                    continue;
                }

                if ft.is_dir() {
                    let scenario_dir = p;
                    let scenario_name = scenario_dir
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("scenario")
                        .to_string();

                    let output_path = workspace_dir.join(format!("{}.pcap", scenario_name));
                    compact_pcap(&scenario_dir, &output_path)
                        .with_context(|| format!("Failed to compact POS scenario: {}", scenario_dir.display()))?;
                    pos_files.push(output_path);
                }
            }

            pos_files.sort_by(|a, b| natord::compare(&a.to_string_lossy(), &b.to_string_lossy()));
        } else if pos_input_path.extension().and_then(|s| s.to_str()) == Some("pcap") {
            pos_files.push(pos_input_path.to_owned());
        }

        if pos_files.is_empty() {
            anyhow::bail!("No POS pcap files matched: {}", pos_input_str);
        }

        let neg_pcap_path = Path::new(workspace_dir).join("BENIGM.pcap");
        if let Err(e) = compact_pcap(&neg_glob, &neg_pcap_path) {
            anyhow::bail!("Failed to compact NEG pcaps: {}", e)
        }

        if !neg_pcap_path.exists() {
            anyhow::bail!("NEG pcap not found after compacting: {}", neg_pcap_path.display());
        }

        info!("🚀 Folder-mode Pipeline started. Workspace: {}", workspace_str);
        info!("🎲 NEG Sampling Rate: {:.2}%", sampling_rate * 100.0);
        info!("POS files: {}", pos_files.len());
        info!("NEG file: {}", neg_pcap_path.display());

        for (idx, pos_file) in pos_files.iter().enumerate() {
            let scenario = pos_file.file_stem().and_then(|s| s.to_str()).unwrap_or("pos");

            info!("------------------------------------------------");
            info!(">>> [{}/{}] Scenario: {}", idx + 1, pos_files.len(), scenario);

            run_one_scenario(
                workspace_dir,
                scenario,
                pos_file,
                &neg_pcap_path,
                sampling_rate,
                write_mixed_pcap,
            )?;
        }

        info!("🎉 Pipeline completed successfully.");
        Ok(())
    } else {
        warn!("Unknown mode: {}", mode);
        Ok(())
    }
}
