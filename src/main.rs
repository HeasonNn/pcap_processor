mod common;
mod export;
mod flow;
mod merger;
mod parser;
mod pretrain_cache;
mod stats;

use crate::common::{Args, Command, Config, PretrainFamilyConfig};
use crate::parser::compact_pcap;
use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn};
use serde::Serialize;
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

fn resolve_neg_pcap(shared_neg_pcap: Option<&str>, neg_glob: &str, workspace_dir: impl AsRef<Path>) -> Result<PathBuf> {
    if let Some(shared_path) = shared_neg_pcap {
        let resolved = PathBuf::from(shared_path);
        if !resolved.exists() {
            anyhow::bail!("Shared NEG pcap not found: {}", resolved.display());
        }
        return Ok(resolved);
    }

    let neg_pcap_path = workspace_dir.as_ref().join("BENIGN.pcap");
    compact_pcap(neg_glob, &neg_pcap_path).context("Failed to compact NEG pcaps")?;

    if !neg_pcap_path.exists() {
        anyhow::bail!("NEG pcap not found after compacting: {}", neg_pcap_path.display());
    }

    Ok(neg_pcap_path)
}

#[cfg(test)]
mod tests {
    use super::{build_pretrain_manifest, build_pretrain_manifest_family, resolve_neg_pcap};
    use crate::common::PretrainFamilyConfig;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("pcap_processor_{name}_{nanos}"))
    }

    #[test]
    fn resolve_neg_pcap_prefers_shared_file() {
        let workspace = unique_dir("shared_neg_workspace");
        fs::create_dir_all(&workspace).unwrap();

        let shared_neg = workspace.join("shared_benign.pcap");
        fs::write(&shared_neg, b"pcap").unwrap();

        let resolved = resolve_neg_pcap(
            Some(shared_neg.as_os_str().to_string_lossy().as_ref()),
            "unused-neg-input",
            &workspace,
        )
        .unwrap();

        assert_eq!(resolved, shared_neg);

        let _ = fs::remove_file(&shared_neg);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn existing_config_without_shared_neg_still_parses() {
        let cfg = r#"{
            "global": {
                "mode": "folder",
                "pos_glob": "data/pos",
                "neg_glob": "data/neg",
                "output_dir": "./data/out",
                "neg_sampling_rate": 1.0,
                "write_mixed_pcap": false
            },
            "attacks": []
        }"#;

        let parsed: crate::common::Config = serde_json::from_str(cfg).unwrap();
        assert!(parsed.global.shared_neg_pcap.is_none());
    }

    #[test]
    fn pretrain_manifest_family_uses_relative_family_paths() {
        let entry = build_pretrain_manifest_family("ciciiot2025", "data/shared_neg/CICIIOT2025_BENIGN.pcap");

        assert_eq!(entry.family, "ciciiot2025");
        assert_eq!(entry.source, "data/shared_neg/CICIIOT2025_BENIGN.pcap");
        assert_eq!(entry.data, "ciciiot2025/benign.data");
        assert_eq!(entry.csv, "ciciiot2025/benign.csv");
        assert_eq!(entry.cache, "ciciiot2025/cache");
    }

    #[test]
    fn pretrain_manifest_serializes_root_and_families() {
        let root = unique_dir("pretrain_manifest_root").join("pretrain");
        let manifest = build_pretrain_manifest(
            &root,
            vec![build_pretrain_manifest_family("dohbrw", "dohbrw/BENIGN.pcap")],
        );

        let json = serde_json::to_value(&manifest).unwrap();

        assert_eq!(json["version"], 1);
        assert_eq!(json["root"], root.to_string_lossy().as_ref());
        assert_eq!(json["families"][0]["family"], "dohbrw");
        assert_eq!(json["families"][0]["source"], "dohbrw/BENIGN.pcap");
        assert_eq!(json["families"][0]["data"], "dohbrw/benign.data");
        assert_eq!(json["families"][0]["csv"], "dohbrw/benign.csv");
        assert_eq!(json["families"][0]["cache"], "dohbrw/cache");
    }

    #[test]
    fn resolve_pretrain_family_pcap_prefers_existing_shared_file() {
        let workspace = unique_dir("pretrain_family_shared");
        let family_dir = workspace.join("pretrain").join("dohbrw");
        fs::create_dir_all(&family_dir).unwrap();
        let shared_pcap = workspace.join("shared.pcap");
        fs::write(&shared_pcap, b"pcap").unwrap();

        let family = PretrainFamilyConfig {
            family: "dohbrw".to_string(),
            glob: Some("unused".to_string()),
            shared_pcap: Some(shared_pcap.to_string_lossy().to_string()),
        };

        let (resolved, source) = super::resolve_pretrain_family_pcap(&family, &family_dir).unwrap();

        assert_eq!(resolved, shared_pcap);
        assert_eq!(source, resolved.to_string_lossy());

        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn resolve_pretrain_family_pcap_requires_shared_pcap_or_glob() {
        let family_dir = unique_dir("pretrain_family_missing_source");
        let family = PretrainFamilyConfig {
            family: "ciciiot2025".to_string(),
            glob: None,
            shared_pcap: None,
        };

        let err = super::resolve_pretrain_family_pcap(&family, &family_dir).unwrap_err();

        assert_eq!(err.to_string(), "family 'ciciiot2025' requires shared_pcap or glob");
    }
}

#[derive(Serialize)]
struct PretrainManifest {
    version: u32,
    root: String,
    families: Vec<PretrainManifestFamily>,
}

#[derive(Serialize)]
struct PretrainManifestFamily {
    family: String,
    source: String,
    data: String,
    csv: String,
    cache: String,
}

fn pretrain_family_relative_path(family: &str, name: &str) -> String {
    format!("{family}/{name}")
}

fn build_pretrain_manifest_family(family: &str, source: impl Into<String>) -> PretrainManifestFamily {
    PretrainManifestFamily {
        family: family.to_string(),
        source: source.into(),
        data: pretrain_family_relative_path(family, "benign.data"),
        csv: pretrain_family_relative_path(family, "benign.csv"),
        cache: pretrain_family_relative_path(family, "cache"),
    }
}

fn build_pretrain_manifest(root: impl AsRef<Path>, families: Vec<PretrainManifestFamily>) -> PretrainManifest {
    PretrainManifest {
        version: 1,
        root: root.as_ref().to_string_lossy().to_string(),
        families,
    }
}

fn resolve_pretrain_neg_pcap(config: &Config, workspace_dir: impl AsRef<Path>) -> Result<Option<PathBuf>> {
    if let Some(shared_path) = config.global.shared_pretrain_neg_pcap.as_deref() {
        let resolved = PathBuf::from(shared_path);
        if !resolved.exists() {
            anyhow::bail!("Shared pretrain NEG pcap not found: {}", resolved.display());
        }
        return Ok(Some(resolved));
    }

    if let Some(pretrain_glob) = config.global.pretrain_neg_glob.as_deref() {
        let pretrain_pcap_path = workspace_dir.as_ref().join("PRETRAIN_BENIGN.pcap");
        compact_pcap(pretrain_glob, &pretrain_pcap_path).context("Failed to compact pretrain NEG pcaps")?;
        return Ok(Some(pretrain_pcap_path));
    }

    Ok(None)
}

fn resolve_pretrain_family_pcap(
    family: &PretrainFamilyConfig,
    family_dir: impl AsRef<Path>,
) -> Result<(PathBuf, String)> {
    if let Some(shared_path) = family.shared_pcap.as_deref() {
        let resolved = PathBuf::from(shared_path);
        if resolved.exists() {
            return Ok((resolved, shared_path.to_string()));
        }
        if family.glob.is_none() {
            anyhow::bail!(
                "Shared pretrain pcap not found for family '{}': {}",
                family.family,
                resolved.display()
            );
        }
        warn!(
            "Shared pretrain pcap not found for family '{}': {}; compacting glob instead",
            family.family,
            resolved.display()
        );
    }

    if let Some(pretrain_glob) = family.glob.as_deref() {
        let family_pcap_path = family_dir.as_ref().join("BENIGN.pcap");
        compact_pcap(pretrain_glob, &family_pcap_path)
            .with_context(|| format!("Failed to compact pretrain pcaps for family '{}'", family.family))?;
        if !family_pcap_path.exists() {
            anyhow::bail!(
                "Pretrain pcap not found after compacting family '{}': {}",
                family.family,
                family_pcap_path.display()
            );
        }
        return Ok((
            family_pcap_path,
            pretrain_family_relative_path(&family.family, "BENIGN.pcap"),
        ));
    }

    anyhow::bail!("family '{}' requires shared_pcap or glob", family.family);
}

fn run_pretrain_benign_export(workspace_dir: impl AsRef<Path>, benign_pcap_path: impl AsRef<Path>) -> Result<()> {
    let prefix_path = workspace_dir.as_ref().join("pretrain_benign");
    let prefix_str = prefix_path.to_string_lossy().to_string();
    let benign_pcap_str = benign_pcap_path.as_ref().to_string_lossy().to_string();

    info!("Pretrain benign export: {} -> {}", benign_pcap_str, prefix_str);
    let count = merger::export_benign_dataset(&benign_pcap_str, &prefix_str, false)?;
    info!("✅ Pretrain benign .data generated. Total packets: {}", count);

    let data_file = format!("{}.data", prefix_str);
    let csv_path = format!("{}.csv", prefix_str);
    let engine = flow::FlowEngine::new(5_000_000);
    match engine.run_benign(&data_file, &csv_path) {
        Ok(_) => info!("✅ Pretrain benign flow CSV generated"),
        Err(e) => error!("❌ Pretrain benign flow construction failed: {}", e),
    }
    Ok(())
}

fn run_pretrain_family_export(
    pretrain_root: impl AsRef<Path>,
    family: &PretrainFamilyConfig,
) -> Result<PretrainManifestFamily> {
    let family_dir = pretrain_root.as_ref().join(&family.family);
    ensure_dir(&family_dir)?;

    let (benign_pcap_path, manifest_source) = resolve_pretrain_family_pcap(family, &family_dir)?;
    let prefix_path = family_dir.join("benign");
    let prefix_str = prefix_path.to_string_lossy().to_string();
    let benign_pcap_str = benign_pcap_path.to_string_lossy().to_string();

    info!(
        "Pretrain family export [{}]: {} -> {}",
        family.family, benign_pcap_str, prefix_str
    );
    let count = merger::export_benign_dataset(&benign_pcap_str, &prefix_str, false)
        .with_context(|| format!("Failed to export pretrain family '{}'", family.family))?;
    info!(
        "✅ Pretrain family '{}' .data generated. Total packets: {}",
        family.family, count
    );

    let data_file = format!("{}.data", prefix_str);
    let csv_path = format!("{}.csv", prefix_str);
    let engine = flow::FlowEngine::new(5_000_000);
    engine
        .run_benign(&data_file, &csv_path)
        .with_context(|| format!("Pretrain family '{}' flow CSV generation failed", family.family))?;
    info!("✅ Pretrain family '{}' flow CSV generated", family.family);

    Ok(build_pretrain_manifest_family(&family.family, manifest_source))
}

fn run_pretrain_family_exports(workspace_dir: impl AsRef<Path>, families: &[PretrainFamilyConfig]) -> Result<()> {
    let pretrain_root = workspace_dir.as_ref().join("pretrain");
    ensure_dir(&pretrain_root)?;

    let mut manifest_families = Vec::with_capacity(families.len());
    for family in families {
        manifest_families.push(run_pretrain_family_export(&pretrain_root, family)?);
    }

    let manifest = build_pretrain_manifest(&pretrain_root, manifest_families);
    let manifest_path = pretrain_root.join("manifest.json");
    let manifest_file = File::create(&manifest_path)
        .with_context(|| format!("Failed to create pretrain manifest: {}", manifest_path.display()))?;
    serde_json::to_writer_pretty(manifest_file, &manifest)
        .with_context(|| format!("Failed to write pretrain manifest: {}", manifest_path.display()))?;
    info!("Pretrain manifest written: {}", manifest_path.display());

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

    match args.command {
        Command::Process { config } => process_dataset(&config),
        Command::Stats { config, output } => stats::run_stats(&config, &output),
        Command::PretrainCache {
            data,
            out_dir,
            packet_cutoff,
            flow_timeout_s,
            window_duration_s,
            window_packet_limit,
            shard_flows,
            max_flows,
            timeout_check_interval,
            graph_token_count,
            manifest,
        } => {
            if manifest.is_some() {
                anyhow::bail!("pretrain-cache --manifest is not implemented yet");
            }
            let data = data
                .as_deref()
                .context("pretrain-cache requires --data in single-file mode")?;
            let out_dir = out_dir
                .as_deref()
                .context("pretrain-cache requires --out-dir in single-file mode")?;
            pretrain_cache::run(
                data,
                out_dir,
                packet_cutoff,
                flow_timeout_s,
                window_duration_s,
                window_packet_limit,
                shard_flows,
                max_flows,
                timeout_check_interval,
                graph_token_count,
            )
        },
    }
}

fn process_dataset(config_path: &str) -> Result<()> {
    let file = File::open(config_path).context("Failed to open config file")?;
    let reader = BufReader::new(file);
    let config: Config = serde_json::from_reader(reader).context("Failed to parse config JSON")?;

    let workspace_str = &config.global.output_dir;
    let workspace_dir = Path::new(workspace_str);
    let mode = &config.global.mode;
    let sampling_rate = config.global.neg_sampling_rate;
    let write_mixed_pcap = config.global.write_mixed_pcap.unwrap_or(true);

    ensure_dir(workspace_dir)?;

    if let Some(pretrain_families) = config
        .global
        .pretrain_families
        .as_deref()
        .filter(|families| !families.is_empty())
    {
        run_pretrain_family_exports(workspace_dir, pretrain_families)?;
        if config.attacks.is_empty() {
            info!("Pretrain families exported; no attacks configured, skipping scenario processing.");
            return Ok(());
        }
    } else if let Some(pretrain_neg_pcap) = resolve_pretrain_neg_pcap(&config, workspace_dir)? {
        run_pretrain_benign_export(workspace_dir, &pretrain_neg_pcap)?;
    } else {
        info!("No pretrain_neg_glob/shared_pretrain_neg_pcap configured; skipping standalone pretrain benign export.");
    }

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

                if ft.is_file() || ft.is_symlink() {
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

        let neg_pcap_path = resolve_neg_pcap(config.global.shared_neg_pcap.as_deref(), neg_glob, workspace_dir)?;

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
