use std::{
    collections::HashMap,
    convert::TryFrom,
    io::BufRead,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
    time::SystemTime,
};

use anyhow::{bail, Context, Result};
use mongodb::bson;
use regex::Regex;

use crate::{configuration, datamodel, filesystem, storage::Store};

const MTIME_THRESHOLD: Duration = Duration::from_secs(60);
const KEYS_COLLECTION_PREFIX: &str = "keys";

pub(crate) fn process(
    args: configuration::Configuration,
    term_token: &Arc<AtomicBool>,
) -> Result<()> {
    let db = mongodb::sync::Client::with_options(args.options)?.database(&args.db_name);
    let mut store = Store::new(&db);
    let threshold = SystemTime::now() - MTIME_THRESHOLD;
    for path in filesystem::get_paths(args.files)? {
        if term_token.load(Ordering::Relaxed) {
            bail!("Terminated at path iteration");
        }

        process_entry(
            &path,
            threshold,
            &mut store,
            &term_token,
            args.sni_filter.as_ref(),
        )?;
    }

    Ok(())
}

fn process_entry(
    path: &std::path::Path,
    threshold: SystemTime,
    store: &mut Store,
    term_token: &Arc<AtomicBool>,
    sni_filter: Option<&Regex>,
) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for entry {}", path.display()))?;
    if !metadata.is_file() {
        return Ok(());
    }

    let mtime = metadata
        .modified()
        .with_context(|| format!("Failed to get mtime for file {}", path.display()))?;
    if mtime > threshold {
        return Ok(());
    }

    process_file(path, store, term_token, sni_filter)?;

    Ok(())
}

fn process_file(
    path: &std::path::Path,
    store: &mut Store,
    term_token: &Arc<AtomicBool>,
    sni_filter: Option<&Regex>,
) -> Result<()> {
    let file_name = &path.display();

    println!("{}: open", file_name);
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open file {}", file_name))?;
    let lines = std::io::BufReader::new(file).lines();
    process_lines(lines, file_name, store, term_token, sni_filter)?;

    std::fs::remove_file(&path)
        .with_context(|| format!("Failed to remove file {}", path.display()))?;

    println!("{}: done", file_name);
    Ok(())
}

fn process_lines<'a, Lines, Line, Error>(
    lines: Lines,
    file_name: &impl std::fmt::Display,
    store: &mut Store,
    term_token: &Arc<AtomicBool>,
    sni_filter: Option<&Regex>,
) -> Result<()>
where
    Lines: IntoIterator<Item = Result<Line, Error>>,
    Line: AsRef<str> + 'a,
    Error: std::error::Error + Send + Sync + 'static,
{
    let mut batch_map = HashMap::<String, Vec<bson::Document>>::new();
    let mut line_num: u64 = 0;
    for line in lines {
        line_num += 1;
        let context = ParseContext {
            file_name,
            line_num,
        };

        if term_token.load(Ordering::Relaxed) {
            bail!("Terminated at {}", context);
        }

        let line = line.with_context(|| format!("Failed to read line at {}", context))?;
        let record = datamodel::Record::try_from(line.as_ref())
            .with_context(|| format!("Failed to parse at {}", context))?;

        if sni_filter
            .map(|f| !f.is_match(&record.sni))
            .unwrap_or(false)
        {
            continue;
        }

        let collection_name = format!(
            "{}_{}:{}_{}",
            KEYS_COLLECTION_PREFIX, record.server_ip, record.server_port, record.sni
        );
        let batch = batch_map
            .entry(collection_name.clone())
            .or_insert_with(Vec::new);

        batch.push(bson::Document::from(record));

        const BATCH_SIZE: usize = 1000;
        if batch.len() >= BATCH_SIZE {
            println!("{}: writing to {}", file_name, collection_name);
            let batch = batch_map.remove(&collection_name).unwrap();
            store.write(&collection_name, batch).with_context(|| {
                format!("Failed to write to {} for {}", collection_name, file_name)
            })?;
        }
    }

    for (collection_name, batch) in batch_map {
        if term_token.load(Ordering::Relaxed) {
            bail!("Terminated at flushing for {}", file_name);
        }

        let count = batch.len();
        println!("{}: flushing {} to {}", file_name, count, collection_name);
        store.write(&collection_name, batch).with_context(|| {
            format!(
                "Failed to flush {} to {} for {}",
                count, collection_name, file_name
            )
        })?;
    }

    Ok(())
}

struct ParseContext<'a> {
    pub file_name: &'a dyn std::fmt::Display,
    pub line_num: u64,
}

impl std::fmt::Display for ParseContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.file_name, self.line_num))
    }
}
