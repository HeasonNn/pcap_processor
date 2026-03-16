# PROJECT KNOWLEDGE BASE

**Generated:** 2026-02-22
**Commit:** 603eba1
**Branch:** main

## OVERVIEW
Rust CLI for processing PCAP network captures into labeled flow-based datasets for ML/security research. Supports rule-based attack labeling and folder-based batch processing.

## STRUCTURE
```
pcap_processor/
├── src/
│   ├── main.rs      # Entry point, CLI, pipeline orchestration
│   ├── parser.rs    # PCAP parsing, packet filtering, link-layer handling
│   ├── merger.rs    # Merge strategies (hash-sampling, budget-control)
│   ├── flow.rs      # Flow construction from packets (parallel)
│   ├── common.rs    # Config structs, FlowKey, PacketMeta
│   └── export.rs    # DatasetWriter (.data/.label), CsvExporter
├── config/          # JSON config files per dataset (IDS2017, UNSW, etc.)
└── data/            # Symlink to PCAP data (../tmp/pcap)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add new merge strategy | `src/merger.rs` | Implement `MergeStrategy` trait |
| Parse new link-layer | `src/parser.rs:11-52` | `decode_l2()` handles Ethernet/SLL/RAW |
| Add flow features | `src/flow.rs:152-250` | `FlowAccumulator::finalize()` |
| New config field | `src/common.rs:14-31` | `GlobalConfig` struct |
| CLI args | `src/common.rs:47-52` | `Args` struct with clap |
| Dataset output format | `src/export.rs` | `DatasetWriter` / `CsvExporter` |

## CONVENTIONS
- **Edition 2024** (Rust) — uses modern features
- **Error handling**: `anyhow::Result` everywhere; use `.context()` for messages
- **Logging**: `log` crate + `env_logger`; INFO level default
- **Concurrency**: `rayon` for parallel batch processing; `crossbeam` channels for streaming
- **Imports**: `group_imports = "StdExternalCrate"` (see rustfmt.toml)
- **Max width**: 120 chars

## ANTI-PATTERNS (THIS PROJECT)
- Typo in `main.rs:201`: `BENIGM.pcap` (should be `BENIGN.pcap`) — will cause file not found
- `tokio` in Cargo.toml but `#[tokio::main]` not used — main is synchronous

## UNIQUE STYLES
- **Two processing modes**:
  1. `rules` mode: Filter raw PCAP by IP/time rules → split into attack types
  2. `folder` mode: Compact existing attack/benign folders → merge
- **Merge strategies** selectable via env vars:
  - Default: `HashSamplingStrategy` with configurable rate
  - Budget control: Set `PCAP_MERGE_TOTAL_PKTS` + `PCAP_MERGE_ATTACK_RATIO`
- **Config-driven**: All scenarios defined in JSON config files under `config/`

## COMMANDS
```bash
# Run with config
cargo run -- --config config/test/test_config.json

# Build release
cargo build --release

# Format code
cargo fmt

# Run with budget control (alternative merge)
PCAP_MERGE_TOTAL_PKTS=1000000 PCAP_MERGE_ATTACK_RATIO=0.1 \
  cargo run -- --config config/ids2017/friday.json
```

## NOTES
- **Link-layer handling**: Supports Ethernet (DLT_EN10MB), SLL (113), RAW (12); auto-wraps to Ethernet
- **Flow timeout**: 120 seconds (`FLOW_TIMEOUT_NS` in flow.rs)
- **Dataset output**: `.data` file (space-separated packet info) + `.label` file (0/1 per packet)
- **No tests directory**: Project relies on manual testing with config files
- **Chinese comments** in Cargo.toml for crossbeam-channel usage
