# Family-Aware Pretrain And Hugging Face Upload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split pretraining exports and cache shards by dataset-level traffic family, then upload the family-organized dataset artifacts to the existing Hugging Face dataset repo.

**Architecture:** Extend `pcap_processor` so `process` can export pretrain data per configured family, and `pretrain-cache` can build cache shards from a generated manifest. Keep old single-source pretrain fields working for backward compatibility. Upload the final organized dataset tree to `HeasoNnn/TrafficDataset` using the existing Hugging Face upload environment.

**Tech Stack:** Rust 2024, `serde`, `serde_json`, `ndarray-npy`, existing `pcap_processor` CLI, Python `huggingface_hub` from `/home/hs/workspace/Glance_PT/.venv_hf_upload`.

---

## File Map

- Modify `src/common.rs`: add `PretrainFamilyConfig`, add `pretrain_families`, and add manifest-mode CLI args.
- Modify `src/main.rs`: resolve/export each dataset-level pretrain family and write `pretrain/manifest.json`.
- Modify `src/pretrain_cache.rs`: expose reusable manifest structs and implement manifest-driven cache builds.
- Modify `src/merger.rs`: keep standalone benign export behavior; add tests only if new call sites require it.
- Modify `README.md`: document family-aware pretrain export/cache/upload workflow.
- Add tests in existing `#[cfg(test)]` modules: old config compatibility, family manifest generation, manifest cache argument parsing.
- Add optional script `scripts/upload_hf_dataset.py`: controlled upload helper for `HeasoNnn/TrafficDataset`.
- Output data under `data/pretrain/<family>/...` or the configured `output_dir/pretrain/<family>/...`.

## Target Layout

```text
<output_dir>/pretrain/
  manifest.json
  ciciiot2025/
    benign.data
    benign.csv
    cache/
      metadata.json
      shard_000000.npz
  dohbrw/
    benign.data
    benign.csv
    cache/
      metadata.json
      shard_000000.npz
  cic_apt_iiot2024/
    benign.data
    benign.csv
    cache/
      metadata.json
      shard_000000.npz
```

`manifest.json` shape:

```json
{
  "version": 1,
  "root": "/abs/path/to/output_dir/pretrain",
  "families": [
    {
      "family": "ciciiot2025",
      "source": "data/shared_neg/CICIIOT2025_BENIGN.pcap",
      "data": "ciciiot2025/benign.data",
      "csv": "ciciiot2025/benign.csv",
      "cache": "ciciiot2025/cache"
    }
  ]
}
```

## Task 1: Extend Config And CLI Types

**Files:**
- Modify: `src/common.rs`

- [ ] Add `PretrainFamilyConfig`.

```rust
#[derive(Deserialize, Clone, Debug)]
pub struct PretrainFamilyConfig {
    pub family: String,
    pub glob: Option<String>,
    pub shared_pcap: Option<String>,
}
```

- [ ] Add to `GlobalConfig`.

```rust
pub pretrain_families: Option<Vec<PretrainFamilyConfig>>,
```

- [ ] Extend `Command::PretrainCache` with optional manifest mode.

```rust
#[arg(long)]
manifest: Option<String>,
```

Keep `data` and `out_dir` as `Option<String>` so either single-file mode or manifest mode can be used.

- [ ] Add tests proving old configs without `pretrain_families` still parse.

Run: `cargo test existing_config_without_shared_neg_still_parses`

Expected: test passes.

## Task 2: Generate Family Pretrain Manifest During `process`

**Files:**
- Modify: `src/main.rs`

- [ ] Create structs for manifest serialization near the pretrain export helpers.

```rust
#[derive(serde::Serialize)]
struct PretrainManifest {
    version: u32,
    root: String,
    families: Vec<PretrainManifestFamily>,
}

#[derive(serde::Serialize)]
struct PretrainManifestFamily {
    family: String,
    source: String,
    data: String,
    csv: String,
    cache: String,
}
```

- [ ] Replace single `run_pretrain_benign_export` call with:
  - If `pretrain_families` exists and is non-empty, export each family.
  - Else use legacy `pretrain_neg_glob/shared_pretrain_neg_pcap`.

- [ ] Family resolution rules:
  - `shared_pcap` exists: use it directly and fail if missing.
  - otherwise `glob` exists: compact it to `<output_dir>/pretrain/<family>/BENIGN.pcap`.
  - neither exists: fail with `family '<name>' requires shared_pcap or glob`.

- [ ] For each family, write:

```text
<output_dir>/pretrain/<family>/benign.data
<output_dir>/pretrain/<family>/benign.csv
```

- [ ] Write manifest after all family exports:

```text
<output_dir>/pretrain/manifest.json
```

- [ ] Add unit tests for manifest path calculation using temporary directories and a tiny shared pcap fixture.

Run: `cargo test pretrain`

Expected: family manifest generation tests pass.

## Task 3: Add Manifest Mode To `pretrain-cache`

**Files:**
- Modify: `src/pretrain_cache.rs`
- Modify: `src/main.rs`

- [ ] Add manifest deserialization structs matching Task 2 output.

```rust
#[derive(serde::Deserialize)]
struct PretrainManifest {
    root: String,
    families: Vec<PretrainManifestFamily>,
}

#[derive(serde::Deserialize)]
struct PretrainManifestFamily {
    family: String,
    data: String,
    cache: String,
}
```

- [ ] Add a public function:

```rust
pub fn run_manifest(
    manifest_path: &str,
    packet_cutoff: usize,
    flow_timeout_s: u64,
    window_duration_s: u64,
    window_packet_limit: usize,
    shard_flows: usize,
    max_flows: usize,
    timeout_check_interval: usize,
    graph_token_count: usize,
) -> Result<()>
```

- [ ] For each family:
  - Resolve `data` and `cache` relative to manifest `root`.
  - Call existing `run(data, cache, ...)`.
  - Log family name and output path.

- [ ] Keep single-file mode:

```bash
cargo run -- pretrain-cache --data path/to/benign.data --out-dir path/to/cache
```

- [ ] Add manifest mode:

```bash
cargo run -- pretrain-cache --manifest data/experiments/pretrain/manifest.json --window-packet-limit 2000
```

- [ ] Validate CLI errors:
  - `--manifest` cannot be combined with `--data/--out-dir`.
  - single-file mode requires both `--data` and `--out-dir`.

Run: `cargo test pretrain_cache`

Expected: manifest path and argument validation tests pass.

## Task 4: Update Dataset Configs For Dataset-Level Families

**Files:**
- Modify or add config under `config/pretrain/` or current dataset configs.

- [ ] Add a dedicated config:

```text
config/pretrain/families.json
```

with dataset-level families:

```json
{
  "global": {
    "mode": "folder",
    "output_dir": "data/pretrain_family",
    "pos_glob": "data/placeholder/pos",
    "neg_glob": "data/placeholder/neg",
    "neg_sampling_rate": 1.0,
    "write_mixed_pcap": false,
    "pretrain_families": [
      {
        "family": "ciciiot2025",
        "shared_pcap": "data/shared_neg/CICIIOT2025_BENIGN.pcap"
      },
      {
        "family": "dohbrw",
        "glob": "data/dohbrw/benign/all"
      },
      {
        "family": "cic_apt_iiot2024",
        "shared_pcap": "data/raw/CIC_APT_IIoT2024/downloaded_CICAPT_IIoT/CICAPT-IIoT Dataset/Network_Traffic/Phase1/1stPhase-timed-Merged.pcap"
      }
    ]
  },
  "attacks": []
}
```

- [ ] Adjust placeholder paths to actual local paths before running.

- [ ] Decide whether `process` should skip normal POS/NEG processing when `attacks` is empty and only `pretrain_families` is set. Recommended behavior: export pretrain families and return early.

Run: `cargo test`

Expected: all tests pass.

## Task 5: Build Family-Aware Local Artifacts

**Files/Data:**
- Output: `data/pretrain_family/pretrain/manifest.json`
- Output: `data/pretrain_family/pretrain/<family>/benign.data`
- Output: `data/pretrain_family/pretrain/<family>/benign.csv`
- Output: `data/pretrain_family/pretrain/<family>/cache/*.npz`

- [ ] Export per-family `.data/.csv`.

```bash
cargo run --release -- process --config config/pretrain/families.json
```

Expected:

```text
data/pretrain_family/pretrain/manifest.json exists
data/pretrain_family/pretrain/ciciiot2025/benign.data exists
data/pretrain_family/pretrain/dohbrw/benign.data exists
data/pretrain_family/pretrain/cic_apt_iiot2024/benign.data exists
```

- [ ] Build per-family cache.

```bash
cargo run --release -- pretrain-cache \
  --manifest data/pretrain_family/pretrain/manifest.json \
  --window-packet-limit 2000 \
  --shard-flows 50000
```

Expected:

```text
data/pretrain_family/pretrain/<family>/cache/metadata.json exists for each family
```

- [ ] Run sanity checks.

```bash
python3 -m json.tool data/pretrain_family/pretrain/manifest.json >/dev/null
find data/pretrain_family/pretrain -name metadata.json -print
```

Expected: valid JSON and one cache metadata file per family.

## Task 6: Prepare Hugging Face Upload Payload

**Files/Data:**
- Source: `data/pretrain_family/pretrain`
- Destination inside HF repo: `pretrain_family/`
- Existing repo: `HeasoNnn/TrafficDataset`

- [ ] Create upload staging folder if needed:

```text
/home/hs/workspace/Glance_PT/datasets/pretrain_family/
```

- [ ] Copy or rsync generated family tree into that folder:

```bash
rsync -a --info=progress2 data/pretrain_family/pretrain/ /home/hs/workspace/Glance_PT/datasets/pretrain_family/
```

- [ ] Add a dataset README fragment:

```text
/home/hs/workspace/Glance_PT/datasets/pretrain_family/README.md
```

containing:

```markdown
# Family-Aware Pretrain Dataset

This folder contains dataset-level traffic-family pretraining artifacts.

Families:
- ciciiot2025
- dohbrw
- cic_apt_iiot2024

Each family contains `benign.data`, `benign.csv`, and `cache/` shards generated by `pcap_processor pretrain-cache`.
```

## Task 7: Upload To Hugging Face

**Files:**
- Use: `/home/hs/workspace/Glance_PT/.venv_hf_upload`
- Existing script reference: `/home/hs/workspace/Glance_PT/logs/hf_upload/upload_traffic_dataset.py`

- [ ] Use the existing token setup if still available. Do not print tokens.

- [ ] Run upload from the HF venv:

```bash
HTTPS_PROXY=http://127.0.0.1:7890 \
HTTP_PROXY=http://127.0.0.1:7890 \
/home/hs/workspace/Glance_PT/.venv_hf_upload/bin/python scripts/upload_hf_dataset.py \
  --repo-id HeasoNnn/TrafficDataset \
  --folder /home/hs/workspace/Glance_PT/datasets \
  --path-in-repo .
```

- [ ] If `scripts/upload_hf_dataset.py` is not added, run a one-off Python upload using `HfApi.upload_large_folder` with:
  - `repo_id="HeasoNnn/TrafficDataset"`
  - `repo_type="dataset"`
  - `folder_path="/home/hs/workspace/Glance_PT/datasets"`
  - `num_workers=4`
  - `ignore_patterns=["**/.DS_Store", "**/__pycache__/**", "**/*.tmp"]`

- [ ] Log upload to:

```text
/home/hs/workspace/Glance_PT/logs/hf_upload/pretrain_family_upload_YYYYMMDD_HHMMSS.log
```

- [ ] Verify remote visibility:

```bash
/home/hs/workspace/Glance_PT/.venv_hf_upload/bin/python - <<'PY'
from huggingface_hub import HfApi
api = HfApi()
files = api.list_repo_files("HeasoNnn/TrafficDataset", repo_type="dataset")
for path in files:
    if path.startswith("pretrain_family/manifest.json") or path.endswith("/cache/metadata.json"):
        print(path)
PY
```

Expected: `pretrain_family/manifest.json` and family cache metadata paths are listed.

## Task 8: Verification And Commit

**Files:**
- All code/config/doc changes from previous tasks.

- [ ] Run formatting:

```bash
cargo fmt
```

Expected: exit 0. Stable rustfmt may warn about nightly-only options already present in `rustfmt.toml`; warnings are acceptable if formatting succeeds.

- [ ] Run tests:

```bash
cargo test
```

Expected: all tests pass.

- [ ] Run release build:

```bash
cargo build --release
```

Expected: release build succeeds.

- [ ] Inspect git status:

```bash
git status -sb
```

Expected: only intended source/config/doc changes are present; generated `.data`, `.csv`, `.pcap`, `.npz`, and logs remain ignored.

- [ ] Commit implementation:

```bash
git add src Cargo.toml Cargo.lock README.md config docs scripts
git commit -m "Add family-aware pretrain exports"
```

- [ ] Push branch:

```bash
git push -u origin codex/pcap-processor-cleanup
```

Expected: remote branch updates successfully.

## Self-Review

- Spec coverage: family-level organization, manifest generation, cache build, HF upload, verification, and backward compatibility are covered.
- Placeholder scan: plan contains no open-ended TODO/TBD placeholders; the only configurable items are concrete local paths that must match actual datasets before execution.
- Type consistency: `PretrainFamilyConfig`, `PretrainManifest`, and `PretrainManifestFamily` are consistently named across tasks.
