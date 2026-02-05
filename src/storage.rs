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

    pub fn write(&mut self, collection_name: &str, batch: impl IntoIterator<Item = bson::Document>) -> Result<()> {
        let collection = self.get_collection(collection_name)?;
        const DUPLICATE_KEY_ERROR_CODE: i32 = 11000;
        match collection.insert_many(batch).ordered(false).run() {
            Ok(_) => Ok(()),
            Err(e) => match e.kind.as_ref() {
                mongodb::error::ErrorKind::InsertMany(mongodb::error::InsertManyError {
                    write_errors: Some(errors),
                    ..
                }) if errors.iter().all(|b| b.code == DUPLICATE_KEY_ERROR_CODE) => Ok(()),
                _ => Err(anyhow!(e)),
            },
        }
    }

    pub fn ensure_collection(&mut self, collection_name: &str) {
        _ = self.get_collection(collection_name)
    }

    fn get_collection(&mut self, collection_name: &str) -> Result<&mut Collection<bson::Document>> {
        Ok(match self.collections.entry(String::from(collection_name)) {
            Occupied(e) => e.into_mut(),
            Vacant(e) => e.insert(create_collection(self.db, collection_name)?),
        })
    }
}

fn create_collection(db: &Database, name: &str) -> Result<Collection<bson::Document>> {
    let collection = db.collection(name);
    let command = doc! {
        "createIndexes": collection.name(),
        "indexes": data_model::get_index_model(),
    };
    db.run_command(command).run().context("Failed to create indexes")?;
    Ok(collection)
}
