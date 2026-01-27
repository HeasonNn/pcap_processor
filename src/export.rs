use crate::common::FlowFeature;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write}; // 引用 common

pub struct CsvExporter {
    writer: BufWriter<File>,
}

impl CsvExporter {
    /// 创建 Exporter 并写入表头
    pub fn new(output_path: &str) -> Result<Self> {
        let file =
            File::create(output_path).with_context(|| format!("Failed to create output CSV: {}", output_path))?;
        let mut writer = BufWriter::new(file);

        // 写入表头
        writeln!(
            writer,
            "src_ip,src_port,dst_ip,dst_port,protocol,timestamp,byteps,pps,duration,\
             pkt_len_mean,pkt_len_std,iat_mean,iat_std,fwd_pkts,bwd_pkts,\
             fwd_segment_size,bwd_segment_size,label"
        )?;

        Ok(Self { writer })
    }

    /// 写入单条记录
    pub fn write_record(&mut self, f: &FlowFeature) -> Result<()> {
        let seconds = f.start_ts / 1_000_000_000;
        let nanoseconds = (f.start_ts % 1_000_000_000) as u32;

        // 使用 chrono 进行时间格式化 (需确保 Cargo.toml 有 chrono)
        let dt = chrono::DateTime::from_timestamp(seconds, nanoseconds).unwrap_or_default();
        let ts_str = dt.format("%m/%d/%Y %H:%M:%S").to_string();

        let label_str = if f.label { "ATTACK" } else { "BENIGN" };

        writeln!(
            self.writer,
            "{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{:.6},{:.6},{}",
            f.src_ip,
            f.src_port,
            f.dst_ip,
            f.dst_port,
            f.protocol,
            ts_str,
            f.byteps,
            f.pps,
            f.duration,
            f.pkt_len_mean,
            f.pkt_len_std,
            f.iat_mean,
            f.iat_std,
            f.fwd_pkts,
            f.bwd_pkts,
            f.fwd_seg_size,
            f.bwd_seg_size,
            label_str
        )?;
        Ok(())
    }

    /// 显式刷新缓冲区 (可选，Drop 时也会自动刷新)
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
