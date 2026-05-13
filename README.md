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

## Development

```bash
cargo fmt
cargo test
cargo build --release
```
