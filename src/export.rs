use crate::common::{FlowFeature,PacketMeta};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct DatasetWriter {
    data_w: BufWriter<File>,
    label_w: BufWriter<File>,
    align_ts_ns: Option<i64>,
}

impl DatasetWriter {
    pub fn new(output_perfix_str: &str) -> Result<Self> {
        Ok(Self {
            data_w: BufWriter::new(File::create(format!("{}.data", output_perfix_str))?),
            label_w: BufWriter::new(File::create(format!("{}.label", output_perfix_str))?),
            align_ts_ns: None,
        })
    }

    #[inline]
    pub fn write_from_meta(&mut self, meta: &PacketMeta, is_pos: bool) -> Result<()> {
        let align = *self.align_ts_ns.get_or_insert(meta.ts_ns);
        let rel_ts = meta.ts_ns - align;

        writeln!(
            self.data_w,
            "{} {} {} {} {} {} {} {}",
            if meta.src_ip.is_ipv4() { 4 } else { 6 },
            meta.src_ip,
            meta.dst_ip,
            meta.src_port,
            meta.dst_port,
            rel_ts,
            meta.packet_code,
            meta.ip_len
        )?;
        self.label_w.write_all(if is_pos { b"1" } else { b"0" })?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.data_w.flush()?;
        self.label_w.flush()?;
        Ok(())
    }
}

pub struct CsvExporter {
    writer: BufWriter<File>,
}

impl CsvExporter {
    pub fn new(output_path: &str) -> Result<Self> {
        let file =
            File::create(output_path).with_context(|| format!("Failed to create output CSV: {}", output_path))?;
        let mut writer = BufWriter::new(file);

        writeln!(
            writer,
            "src_ip,src_port,dst_ip,dst_port,protocol,timestamp,byteps,pps,duration,\
             pkt_len_mean,pkt_len_std,iat_mean,iat_std,fwd_pkts,bwd_pkts,\
             fwd_segment_size,bwd_segment_size,label"
        )?;

        Ok(Self { writer })
    }

    pub fn write_record(&mut self, f: &FlowFeature) -> Result<()> {
        let seconds = f.start_ts / 1_000_000_000;
        let nanoseconds = (f.start_ts % 1_000_000_000) as u32;
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

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
