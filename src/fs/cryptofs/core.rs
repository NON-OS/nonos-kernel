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

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{RwLock, Once};

use super::crypto::generate_nonce;
use super::error::{CryptoFsError, CryptoResult};
use super::types::*;

pub(crate) struct CryptoInner {
    pub block_size: usize,
    pub total_blocks: usize,
    pub files: BTreeMap<String, FileEntry>,
    pub next_inode: AtomicU64,
    pub nonce_counter: AtomicU64,
}

impl core::fmt::Debug for CryptoInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoInner")
            .field("block_size", &self.block_size)
            .field("total_blocks", &self.total_blocks)
            .field("files_count", &self.files.len())
            .field("next_inode", &self.next_inode.load(Ordering::Relaxed))
            .field("nonce_counter", &self.nonce_counter.load(Ordering::Relaxed))
            .finish()
    }
}

#[derive(Debug)]
pub struct CryptoFileSystem {
    pub(crate) inner: RwLock<CryptoInner>,
    pub(crate) stats: RwLock<CryptoFsStatistics>,
}

impl CryptoFileSystem {
    pub(crate) fn new(total_blocks: usize, block_size: usize) -> Self {
        Self {
            inner: RwLock::new(CryptoInner {
                block_size,
                total_blocks,
                files: BTreeMap::new(),
                next_inode: AtomicU64::new(3),
                nonce_counter: AtomicU64::new(0),
            }),
            stats: RwLock::new(CryptoFsStatistics::default()),
        }
    }

    pub fn sync_all(&self) {
    }

    pub fn process_pending_operations(&self, _max_ops: usize) -> usize {
        0
    }

    pub fn stats(&self) -> CryptoFsStatistics {
        let stats = self.stats.read();
        let mut result = stats.clone();

        let inner = self.inner.read();
        result.nonce_counter = inner.nonce_counter.load(Ordering::Relaxed);
        result
    }

    pub fn exists(&self, path: &str) -> bool {
        let inner = self.inner.read();
        inner.files.contains_key(path)
    }

    pub fn get_file_info(&self, path: &str) -> CryptoResult<FileInfo> {
        let inner = self.inner.read();
        let entry = inner.files.get(path).ok_or(CryptoFsError::NotFound)?;

        Ok(FileInfo {
            inode: entry.inode,
            size: entry.plaintext_size(),
            encrypted_size: entry.encrypted.len(),
            created: entry.created_at,
            modified: entry.modified_at,
        })
    }

    pub fn list_files(&self) -> Vec<String> {
        let inner = self.inner.read();
        inner.files.keys().cloned().collect()
    }

    pub fn storage_used(&self) -> usize {
        let inner = self.inner.read();
        inner.files.values().map(|e| e.encrypted.len()).sum()
    }

    pub(crate) fn next_nonce(&self) -> CryptoResult<[u8; NONCE_SIZE]> {
        let inner = self.inner.read();
        inner.nonce_counter.fetch_add(1, Ordering::SeqCst);
        Ok(generate_nonce())
    }
}

pub(crate) static CRYPTOFS: Once<CryptoFileSystem> = Once::new();

pub fn init_cryptofs(total_blocks: usize, block_size: usize) -> CryptoResult<()> {
    CRYPTOFS.call_once(|| CryptoFileSystem::new(total_blocks, block_size));
    Ok(())
}

pub fn get_cryptofs() -> Option<&'static CryptoFileSystem> {
    CRYPTOFS.get()
}

#[inline]
pub(crate) fn require_cryptofs() -> CryptoResult<&'static CryptoFileSystem> {
    CRYPTOFS.get().ok_or(CryptoFsError::NotInitialized)
}
