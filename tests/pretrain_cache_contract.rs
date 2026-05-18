use ndarray::Array1;
use ndarray_npy::NpzReader;
use serde_json::Value;
use std::fs::{self, File};
use std::process::Command;

#[test]
fn pretrain_cache_accepts_8_column_us_rows_and_writes_flow_metadata() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_path = temp.path().join("benign.data");
    let out_dir = temp.path().join("cache");
    fs::write(
        &data_path,
        "4 10.0.0.1 10.0.0.2 12345 443 0 6 60\n\
         4 10.0.0.1 10.0.0.2 12345 443 1 6 60\n",
    )
    .expect("write data");

    let status = Command::new(env!("CARGO_BIN_EXE_pcap_processor"))
        .arg("pretrain-cache")
        .arg("--data")
        .arg(&data_path)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--packet-cutoff")
        .arg("1")
        .arg("--graph-token-count")
        .arg("5")
        .arg("--timestamp-unit")
        .arg("us")
        .arg("--field7-mode")
        .arg("protocol")
        .arg("--source-name")
        .arg("family_a")
        .arg("--source-id")
        .arg("7")
        .status()
        .expect("run pcap_processor");

    assert!(status.success());
    assert!(out_dir.join("metadata.json").exists());
    assert!(out_dir.join("meta.json").exists());

    let metadata: Value = serde_json::from_str(&fs::read_to_string(out_dir.join("metadata.json")).expect("metadata"))
        .expect("parse metadata");
    assert_eq!(metadata["cache_schema_version"], "flow_v2_cache.2");
    assert_eq!(metadata["source_names"][0], "family_a");
    assert_eq!(metadata["source_name_to_id"]["family_a"], 7);
    assert_eq!(metadata["source_flow_counts"]["7"], 2);
    assert_eq!(metadata["event_count"], 2);
    assert_eq!(metadata["total_flows"], 2);
    assert_eq!(metadata["label_counts"]["0"], 2);
    assert_eq!(metadata["raw_timestamp_unit"], "us");
    assert_eq!(metadata["raw_field7_mode"], "protocol");
    assert_eq!(metadata["label_policy"], "segment_max");

    let shard_name = metadata["shards"][0]["name"].as_str().expect("shard name");
    let mut npz = NpzReader::new(File::open(out_dir.join(shard_name)).expect("open shard")).expect("read npz");
    let labels: Array1<i32> = npz.by_name("labels").expect("labels");
    let source_ids: Array1<i16> = npz.by_name("source_ids").expect("source_ids");
    let timestamps: Array1<i64> = npz.by_name("cutoff_timestamp_ns").expect("cutoff_timestamp_ns");

    assert_eq!(labels.to_vec(), vec![0, 0]);
    assert_eq!(source_ids.to_vec(), vec![7, 7]);
    assert_eq!(timestamps.to_vec(), vec![0, 1000]);
}
