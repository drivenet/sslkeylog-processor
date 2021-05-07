use anyhow::{self, Context};
use chrono;
use glob;
use regex::Regex;
use std::{self, fs, io::{self, BufRead}, time};

fn main() -> anyhow::Result<()> {
    let regex = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) ")?;
    let threshold = time::SystemTime::now() + time::Duration::from_secs(60);
    for entry_name in glob::glob(r"C:\Users\xm\Projects\dumps\sslkeylog\nginx-*")?.flat_map(|f| f)
    {
        let metadata = std::fs::metadata(&entry_name).with_context(|| format!("Failed to get metadata for entry {:?}", entry_name))?;
        if !metadata.is_file() {
            continue;
        }

        let mtime = metadata.modified().with_context(|| format!("Failed to get mtime for {:?}", entry_name))?;
        if mtime > threshold {
            continue;
        }
        
        let file = fs::File::open(&entry_name).with_context(|| format!("Failed to open file {:?}", entry_name))?;
        let reader = io::BufReader::new(file);
        let mut line_num: u64 = 0;
        for line in reader.lines().map(|l| l.with_context(|| format!("Failed to read line from file {:?}", entry_name))) {
            let line = line?;
            let captures = regex.captures(&line).with_context(|| format!("Failed to parse line {:?}{}", entry_name, line_num))?;
            let timestamp = &captures[1];
            let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp).with_context(|| format!("Invalid timestamp {} at {:?}{}", timestamp, entry_name, line_num))?;
            line_num += 1;
        }
        println!("Parsed lines: {}", line_num);
        break;
    }

    Ok(())
}
