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

use crate::{
    datamodel::{EnrichedRecord, Record},
    errors, filesystem,
    geolocator::Geolocator,
    logging,
    storage::Store,
};

const MTIME_THRESHOLD: Duration = Duration::from_secs(60);

pub(crate) struct Processor<'a> {
    sni_filter: Option<&'a Regex>,
    term_token: &'a Arc<AtomicBool>,
    store: &'a mut Store<'a>,
    geolocator: Option<&'a Geolocator>,
}

impl<'a> Processor<'a> {
    pub fn new(
        sni_filter: Option<&'a Regex>,
        term_token: &'a Arc<AtomicBool>,
        store: &'a mut Store<'a>,
        geolocator: Option<&'a Geolocator>,
    ) -> Self {
        Self {
            sni_filter,
            term_token,
            store,
            geolocator,
        }
    }

    pub fn process<Patterns>(&mut self, patterns: Patterns) -> Result<()>
    where
        Patterns: IntoIterator,
        Patterns::Item: AsRef<str> + 'a,
    {
        let mut failure = None;
        for path in filesystem::get_paths(patterns)? {
            if self.term_token.load(Ordering::Relaxed) {
                bail!(errors::TerminatedError::from_str("path iteration"));
            }

            if let Err(f) = self.process_entry(&path) {
                logging::print_error(&f);
                if failure.is_none() {
                    failure = Some(f);
                }
            }
        }

        failure
            .map(|f| bail!(f.context("Failed to process files")))
            .unwrap_or(Ok(()))
    }

    fn process_entry(&mut self, path: &std::path::Path) -> Result<()> {
        let mtime = std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .with_context(|| format!("Failed to get mtime for file {}", path.display()))?;
        if mtime > SystemTime::now() - MTIME_THRESHOLD {
            return Ok(());
        }

        self.process_file(path)?;

        Ok(())
    }

    fn process_file(&mut self, path: &std::path::Path) -> Result<()> {
        let file_name = &path.display();

        println!("{}: open", file_name);
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open file {}", file_name))?;
        let lines = std::io::BufReader::new(file).lines();
        self.process_lines(lines, file_name)?;

        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove file {}", path.display()))?;

        println!("{}: done", file_name);
        Ok(())
    }

    fn process_lines<Lines, Line, Error>(
        &mut self,
        lines: Lines,
        file_name: &impl std::fmt::Display,
    ) -> Result<()>
    where
        Lines: IntoIterator<Item = Result<Line, Error>>,
        Line: AsRef<str> + 'a,
        Error: std::error::Error + Send + Sync + 'static,
    {
        let mut batch_map = HashMap::<String, Vec<bson::Document>>::new();
        let mut line_num: u64 = 0;
        let mut failure = None;
        for line in lines {
            line_num += 1;
            let location = FileLocation {
                file_name,
                line_num,
            };

            if self.term_token.load(Ordering::Relaxed) {
                bail!(errors::TerminatedError::new(format!(
                    "processing {}",
                    location
                )));
            }

            if let Err(f) = self.process_line(&location, line, &mut batch_map) {
                logging::print_error(&f);
                if failure.is_none() {
                    failure = Some(f);
                }
            }
        }

        for (collection_name, batch) in batch_map {
            if self.term_token.load(Ordering::Relaxed) {
                bail!(errors::TerminatedError::new(format!(
                    "flushing for {}",
                    file_name
                )));
            }

            let count = batch.len();
            println!("{}: flushing {} to {}", file_name, count, collection_name);
            self.store.write(&collection_name, batch).with_context(|| {
                format!(
                    "Failed to flush {} to {} for {}",
                    count, collection_name, file_name
                )
            })?;
        }

        failure
            .map(|f| bail!(f.context(format!("Failed to process lines of {}", file_name))))
            .unwrap_or(Ok(()))
    }

    fn process_line<Line, Error>(
        &mut self,
        location: &FileLocation,
        line: Result<Line, Error>,
        batch_map: &mut HashMap<String, Vec<bson::Document>>,
    ) -> Result<()>
    where
        Line: AsRef<str> + 'a,
        Error: std::error::Error + Send + Sync + 'static,
    {
        let line = line.with_context(|| format!("Failed to read line at {}", location))?;
        let record = Record::try_from(line.as_ref())
            .with_context(|| format!("Failed to parse at {}", location))?;
        if self
            .sni_filter
            .map(|f| !f.is_match(&record.sni))
            .unwrap_or(false)
        {
            return Ok(());
        }

        let geolocation = self
            .geolocator
            .map(|g| {
                g.locate(record.client_ip).with_context(|| {
                    format!(
                        "Failed to geolocate client {} at {}",
                        record.client_ip, location
                    )
                })
            })
            .transpose()?
            .flatten();

        let collection_name = format!("{}@{}:{}", record.sni, record.server_ip, record.server_port);
        let batch = batch_map
            .entry(collection_name.clone())
            .or_insert_with(Vec::new);

        let document = match geolocation {
            Some(geoname_id) => bson::Document::from(&EnrichedRecord {
                record: &record,
                geoname_id,
            }),
            None => bson::Document::from(&record),
        };

        batch.push(document);

        const BATCH_SIZE: usize = 1000;
        if batch.len() >= BATCH_SIZE {
            println!("{}: writing to {}", location.file_name, collection_name);
            let batch = batch_map.remove(&collection_name).unwrap();
            self.store.write(&collection_name, batch).with_context(|| {
                format!(
                    "Failed to write to {} for {}",
                    collection_name, location.file_name
                )
            })?;
        }

        Ok(())
    }
}

struct FileLocation<'a> {
    pub file_name: &'a dyn std::fmt::Display,
    pub line_num: u64,
}

impl std::fmt::Display for FileLocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.file_name, self.line_num))
    }
}
