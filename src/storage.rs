use std::collections::{
    hash_map::Entry::{Occupied, Vacant},
    HashMap,
};

use anyhow::{anyhow, Context, Result};
use mongodb::{
    bson::{self, doc},
    sync::{Collection, Database},
};

use crate::data_model;

pub(crate) struct Store<'a> {
    db: &'a Database,
    collections: HashMap<String, Collection<bson::Document>>,
}

impl<'a> Store<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self {
            db,
            collections: HashMap::new(),
        }
    }

    pub fn write(
        &mut self,
        collection_name: &str,
        batch: impl IntoIterator<Item = bson::Document>,
    ) -> Result<()> {
        let options = mongodb::options::InsertManyOptions::builder()
            .ordered(false)
            .build();

        let collection = match self.collections.entry(String::from(collection_name)) {
            Occupied(c) => &*c.into_mut(),
            Vacant(e) => e.insert(create_collection(self.db, collection_name)?),
        };

        const DUPLICATE_KEY_ERROR_CODE: i32 = 11000;
        match collection.insert_many(batch, options) {
            Ok(_) => Ok(()),
            Err(e)
                if matches!(
                    e.kind.as_ref(),
                    mongodb::error::ErrorKind::BulkWrite(f)
                    if f.write_concern_error.is_none()
                        && f.write_errors.as_ref().map(|b| b.iter().all(|e| e.code == DUPLICATE_KEY_ERROR_CODE)).unwrap_or(false)
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(anyhow!(e)),
        }
    }
}

fn create_collection(db: &Database, name: &str) -> Result<Collection<bson::Document>> {
    let c = db.collection(name);
    let command = doc! {
        "createIndexes": c.name(),
        "indexes": data_model::get_index_model(),
    };
    db.run_command(command, None)
        .context("Failed to create indexes")?;
    Ok(c)
}
