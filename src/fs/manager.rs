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

use spin::{Once, RwLock};

use super::errors::{FsSubsystemError, FsSubsystemResult};
use super::{cache, cryptofs, ramfs, storage, vfs};

static FILESYSTEM_MANAGER: Once<RwLock<FileSystemManager>> = Once::new();

pub struct FileSystemManager {
    initialized: bool,
    vfs_initialized: bool,
    cryptofs_initialized: bool,
    stats: FileSystemManagerStats,
}

#[derive(Debug, Default, Clone)]
pub struct FileSystemManagerStats {
    pub syncs: u64,
    pub distributed_bytes: u64,
    pub errors: u64,
}

impl FileSystemManager {
    pub(crate) const fn new() -> Self {
        Self {
            initialized: false,
            vfs_initialized: false,
            cryptofs_initialized: false,
            stats: FileSystemManagerStats { syncs: 0, distributed_bytes: 0, errors: 0 },
        }
    }

    pub fn init(&mut self) -> FsSubsystemResult<()> {
        vfs::init_vfs();
        self.vfs_initialized = vfs::get_vfs().is_some();

        match cryptofs::init_cryptofs(1024 * 1024, 4096) {
            Ok(()) => self.cryptofs_initialized = true,
            Err(_) => self.cryptofs_initialized = false,
        }

        if let Some(vfs_ref) = vfs::get_vfs() {
            vfs_ref.mount("/", vfs::FileSystemType::RamFs);
            vfs_ref.mount("/secure", vfs::FileSystemType::CryptoFS);
        }

        let _ = ramfs::init_nonos_filesystem();
        cache::init_all_caches();
        self.initialized = true;
        Ok(())
    }

    pub fn store_distributed_data(&mut self, data: &[u8], path: &str) -> FsSubsystemResult<()> {
        if !self.cryptofs_initialized {
            return Err(FsSubsystemError::CryptoFsNotInitialized);
        }
        cryptofs::create_ephemeral_file(path, data)
            .map_err(|_| FsSubsystemError::WritebackError)?;
        self.stats.distributed_bytes += data.len() as u64;
        Ok(())
    }

    pub fn get_storage_stats(&self) -> (usize, usize) {
        let stats = storage::get_storage_stats();
        (stats.used_bytes, stats.total_bytes)
    }

    pub fn get_statistics(&self) -> FileSystemManagerStats {
        self.stats.clone()
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn increment_syncs(&mut self) {
        self.stats.syncs += 1;
    }
}

pub fn init_filesystem_manager() -> FsSubsystemResult<()> {
    FILESYSTEM_MANAGER.call_once(|| {
        let mut manager = FileSystemManager::new();
        if let Err(e) = manager.init() {
            crate::log::logger::log_err!("Failed to initialize filesystem manager: {}", e.as_str());
        }
        RwLock::new(manager)
    });
    Ok(())
}

pub fn get_filesystem_manager() -> Option<&'static RwLock<FileSystemManager>> {
    FILESYSTEM_MANAGER.get()
}
