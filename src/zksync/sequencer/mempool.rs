// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::zksync::types::{Address, L2Transaction, Nonce, TxHash};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub struct TransactionPool {
    by_hash: BTreeMap<TxHash, L2Transaction>,
    by_sender: BTreeMap<Address, Vec<TxHash>>,
    pending_count: usize,
    max_size: usize,
}

impl TransactionPool {
    pub fn new(max_size: usize) -> Self {
        Self { by_hash: BTreeMap::new(), by_sender: BTreeMap::new(), pending_count: 0, max_size }
    }

    pub fn insert(&mut self, tx: L2Transaction) -> bool {
        if self.pending_count >= self.max_size {
            return false;
        }
        if self.by_hash.contains_key(&tx.hash) {
            return false;
        }
        let hash = tx.hash;
        let sender = tx.from;
        self.by_hash.insert(hash, tx);
        self.by_sender.entry(sender).or_default().push(hash);
        self.pending_count += 1;
        true
    }

    pub fn remove(&mut self, hash: &TxHash) -> Option<L2Transaction> {
        let tx = self.by_hash.remove(hash)?;
        if let Some(hashes) = self.by_sender.get_mut(&tx.from) {
            hashes.retain(|h| h != hash);
        }
        self.pending_count -= 1;
        Some(tx)
    }

    pub fn get(&self, hash: &TxHash) -> Option<&L2Transaction> {
        self.by_hash.get(hash)
    }
    pub fn contains(&self, hash: &TxHash) -> bool {
        self.by_hash.contains_key(hash)
    }
    pub fn len(&self) -> usize {
        self.pending_count
    }
    pub fn is_empty(&self) -> bool {
        self.pending_count == 0
    }

    pub fn get_pending_for(&self, sender: &Address) -> Vec<&L2Transaction> {
        self.by_sender
            .get(sender)
            .map(|hashes| hashes.iter().filter_map(|h| self.by_hash.get(h)).collect())
            .unwrap_or_default()
    }

    pub fn next_nonce_for(&self, sender: &Address, current: Nonce) -> Nonce {
        let pending = self.get_pending_for(sender);
        let max = pending.iter().map(|tx| tx.nonce.0).max().unwrap_or(current.0);
        Nonce(max.max(current.0))
    }

    pub fn drain_batch(&mut self, max: usize) -> Vec<L2Transaction> {
        let hashes: Vec<_> = self.by_hash.keys().take(max).copied().collect();
        hashes.into_iter().filter_map(|h| self.remove(&h)).collect()
    }
}

impl Default for TransactionPool {
    fn default() -> Self {
        Self::new(10000)
    }
}
