//! The login picked for a site on one connection: per-connection approvals that end with the
//! approvals epoch, over the choices that stay until log out.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use vk_vault::model::ItemId;

use super::choices::ChoiceStore;

const MAX_REMEMBERED: usize = 32;

pub struct Remembered {
    epoch: u64,
    items: HashMap<String, ItemId>,
    choices: Arc<Mutex<ChoiceStore>>,
    /// The connection's paired public key, base64, as the choice store keys it.
    key: String,
}

impl Remembered {
    pub fn new(epoch: u64, choices: Arc<Mutex<ChoiceStore>>, key: String) -> Self {
        Self {
            epoch,
            items: HashMap::new(),
            choices,
            key,
        }
    }

    fn sync(&mut self, epoch: u64) {
        if self.epoch != epoch {
            self.items.clear();
            self.epoch = epoch;
        }
    }

    /// This connection's approval if the epoch still holds, else the persisted choice.
    pub fn get(&mut self, epoch: u64, origin: &str) -> Option<ItemId> {
        self.sync(epoch);
        self.items
            .get(origin)
            .cloned()
            .or_else(|| self.persisted(origin))
    }

    /// The choice that outlives locks and reconnects; no approval of this connection.
    pub fn persisted(&self, origin: &str) -> Option<ItemId> {
        self.choices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.key, origin)
    }

    /// A failing disk write is logged and leaves the fill alone: the approval still holds for
    /// this connection.
    pub fn insert(&mut self, epoch: u64, origin: String, item: ItemId) {
        self.sync(epoch);
        let stored = self
            .choices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(&self.key, &origin, &item);
        if let Err(error) = stored {
            tracing::warn!(%error, "cannot remember the picked login");
        }
        if self.items.len() >= MAX_REMEMBERED && !self.items.contains_key(&origin) {
            self.items.clear();
        }
        self.items.insert(origin, item);
    }
}
