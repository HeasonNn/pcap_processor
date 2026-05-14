# pcap_processor

Rust CLI for turning raw PCAP traffic into labeled packet/flow datasets and
pretraining cache shards.

## Commands

Process configured datasets:

```bash
cargo run -- process --config config/<dataset>.json
```

Scan raw PCAP/ZIP sources and write dataset statistics:

```bash
cargo run -- stats --config config/<stats>.json --output artifacts/stats.json
```

Build pretraining token shards from a `.data` export:

```bash
cargo run -- pretrain-cache \
  --data artifacts/pretrain_benign.data \
  --out-dir artifacts/pretrain_cache \
  --window-packet-limit 2000
```

Build dataset-level pretraining families:

```bash
cargo run --release -- process --config config/pretrain/families.json
cargo run --release -- pretrain-cache \
  --manifest data/pretrain_family/pretrain/manifest.json \
  --window-packet-limit 2000 \
  --shard-flows 50000
```

This pretrain-only config exports each family under
`data/pretrain_family/pretrain/<family>/` with `benign.data`, `benign.csv`, and a
family `cache/` directory. The manifest at
`data/pretrain_family/pretrain/manifest.json` is the entry point for cache
generation, and `data/pretrain_family/pretrain/` is the high-level staging path
for Hugging Face upload.

## Development

```bash
cargo fmt
cargo test
cargo build --release
```
