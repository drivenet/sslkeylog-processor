use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;

use crate::{configuration, processor, storage};

pub(crate) fn process(args: &configuration::Configuration, term_token: &Arc<AtomicBool>) -> Result<()> {
    let db = mongodb::sync::Client::with_options(args.options.clone())?.database(&args.db_name);
    let mut store = storage::Store::new(&db);
    let mut context = processor::Processor::new(args.filter.as_ref(), term_token, &mut store, args.input_format);
    context.process(&args.files)
}
