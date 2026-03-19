//! In-memory repository implementations for SDK state types.
//!
//! The SDK expects client-managed repositories for several state types
//! (LocalUserDataKeyState, EphemeralPinEnvelopeState, etc.) that the consuming
//! application must provide. We provide simple in-memory implementations.

use bitwarden_state::repository::{Repository, RepositoryError, RepositoryItem};
use std::collections::HashMap;
use std::hash::Hash;
use tokio::sync::RwLock;

/// A generic in-memory repository backed by a HashMap.
pub struct InMemoryRepository<V: RepositoryItem> {
    store: RwLock<HashMap<String, V>>,
}

impl<V: RepositoryItem> InMemoryRepository<V> {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

fn key_to_string<K: Hash + std::fmt::Debug>(key: K) -> String {
    format!("{key:?}")
}

#[async_trait::async_trait]
impl<V> Repository<V> for InMemoryRepository<V>
where
    V: RepositoryItem + Clone + Send + Sync + 'static,
    V::Key: Hash + Eq + std::fmt::Debug + Send + Sync,
{
    async fn get(&self, key: V::Key) -> Result<Option<V>, RepositoryError> {
        let store = self.store.read().await;
        Ok(store.get(&key_to_string(&key)).cloned())
    }

    async fn list(&self) -> Result<Vec<V>, RepositoryError> {
        let store = self.store.read().await;
        Ok(store.values().cloned().collect())
    }

    async fn set(&self, key: V::Key, value: V) -> Result<(), RepositoryError> {
        let mut store = self.store.write().await;
        store.insert(key_to_string(&key), value);
        Ok(())
    }

    async fn set_bulk(&self, values: Vec<(V::Key, V)>) -> Result<(), RepositoryError> {
        let mut store = self.store.write().await;
        for (key, value) in values {
            store.insert(key_to_string(&key), value);
        }
        Ok(())
    }

    async fn remove(&self, key: V::Key) -> Result<(), RepositoryError> {
        let mut store = self.store.write().await;
        store.remove(&key_to_string(&key));
        Ok(())
    }

    async fn remove_bulk(&self, keys: Vec<V::Key>) -> Result<(), RepositoryError> {
        let mut store = self.store.write().await;
        for key in keys {
            store.remove(&key_to_string(&key));
        }
        Ok(())
    }

    async fn remove_all(&self) -> Result<(), RepositoryError> {
        let mut store = self.store.write().await;
        store.clear();
        Ok(())
    }
}
