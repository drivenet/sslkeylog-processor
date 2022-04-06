use std::sync::{atomic::AtomicBool, Arc};

use anyhow::{Context, Result};

use crate::{configuration, geolocator, processor, storage};

pub(crate) fn process(
    args: &configuration::Configuration,
    term_token: &Arc<AtomicBool>,
) -> Result<()> {
    let db = mongodb::sync::Client::with_options(args.options.clone())?.database(&args.db_name);
    let mut store = storage::Store::new(&db);
    let geolocator = args
        .geodb_path
        .as_ref()
        .map(|path| {
            geolocator::Geolocator::new(path).with_context(|| {
                format!("Failed to create geolocator with database path {:?}", path)
            })
        })
        .transpose()?;
    let mut context = processor::Processor::new(
        args.sni_filter.as_ref(),
        term_token,
        &mut store,
        geolocator.as_ref(),
    );
    context.process(&args.files)
}
