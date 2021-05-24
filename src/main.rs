mod configuration;
mod datamodel;
mod filesystem;
mod to_bson;

#[macro_use]
extern crate lazy_static;

use std::{convert::TryFrom, io::BufRead, time::Duration, time::SystemTime};

use anyhow::{anyhow, Context, Result};
use mongodb::bson::{self, doc};

const MTIME_THRESHOLD: Duration = Duration::from_secs(90);
const KEYS_COLLECTION_NAME: &str = "keys";

fn main() -> Result<()> {
    let args = configuration::parse_args(&std::env::args().collect::<Vec<_>>())?;

    let db = mongodb::sync::Client::with_options(args.options)?.database(&args.db_name);
    let keys_collection = get_collections(&db)?;

    let threshold = SystemTime::now() - MTIME_THRESHOLD;
    for path in filesystem::get_paths(args.files)? {
        process_entry(&path, threshold, &keys_collection)?;
    }

    Ok(())
}

fn get_collections(db: &mongodb::sync::Database) -> Result<mongodb::sync::Collection> {
    let keys_collection = db.collection(KEYS_COLLECTION_NAME);
    let command = doc! {
        "createIndexes": keys_collection.name(),
        "indexes": datamodel::get_index_model(),
    };
    db.run_command(command, None)
        .context("Failed to create indexes")?;

    Ok(keys_collection)
}

fn process_entry(
    path: &std::path::Path,
    threshold: SystemTime,
    keys_collection: &mongodb::sync::Collection,
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

    process_file(path, keys_collection)?;

    Ok(())
}

fn process_file(path: &std::path::Path, keys_collection: &mongodb::sync::Collection) -> Result<()> {
    let file_name = &path.display();

    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open file {}", file_name))?;
    let lines = std::io::BufReader::new(file)
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to read line from file {}", file_name))?;

    process_lines(lines, file_name, keys_collection)?;

    std::fs::remove_file(&path)
        .with_context(|| format!("Failed to remove file {}", path.display()))?;

    Ok(())
}

fn process_lines<'a, Lines: IntoIterator>(
    lines: Lines,
    file_name: &impl std::fmt::Display,
    keys_collection: &mongodb::sync::Collection,
) -> Result<()>
where
    Lines::Item: 'a + AsRef<str>,
{
    let mut batch: Vec<bson::Document> = Vec::new();
    let mut line_num: u64 = 0;
    for line in lines {
        line_num += 1;
        let context = ParseContext {
            file_name,
            line_num,
        };

        let record = datamodel::Record::try_from(line.as_ref())
            .with_context(|| format!("Failed to parse at {}", context))?;
        batch.push(bson::Document::from(record));

        const BATCH_SIZE: usize = 1000;
        if batch.len() >= BATCH_SIZE {
            write_batch(&keys_collection, batch)
                .with_context(|| format!("Failed to write batch at {}", context))?;
            batch = Vec::new();
        }
    }

    if !batch.is_empty() {
        write_batch(&keys_collection, batch)
            .with_context(|| format!("Failed to write final batch for {}", file_name))?;
    }

    println!("{}: {}", file_name, line_num);
    Ok(())
}

fn write_batch(
    keys_collection: &mongodb::sync::Collection,
    batch: impl IntoIterator<Item = bson::Document>,
) -> Result<()> {
    let options = mongodb::options::InsertManyOptions::builder()
        .ordered(false)
        .build();

    const DUPLICATE_KEY_ERROR_CODE: i32 = 11000;
    match keys_collection.insert_many(batch, options) {
        Ok(_) => Ok(()),
        Err(e)
            if matches!(
                e.kind.as_ref(),
                mongodb::error::ErrorKind::BulkWriteError(f)
                if f.write_concern_error.is_none()
                    && f.write_errors.as_ref().map(|b| b.iter().all(|e| e.code == DUPLICATE_KEY_ERROR_CODE)).unwrap_or(false)
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(anyhow!(e)),
    }
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
