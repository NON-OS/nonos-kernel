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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::VirtAddr;

use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::loader::ElfImage;

static NEXT_CACHE_ID: AtomicUsize = AtomicUsize::new(1);

fn next_cache_id() -> usize {
    NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheEntryState {
    Loading,
    Ready,
    Failed,
    Unloading,
}

#[derive(Debug)]
pub struct CachedImage {
    pub id: usize,
    pub name: String,
    pub image: ElfImage,
    pub ref_count: usize,
    pub state: CacheEntryState,
    pub load_time: u64,
}

impl CachedImage {
    pub fn new(name: String, image: ElfImage) -> Self {
        Self {
            id: next_cache_id(),
            name,
            image,
            ref_count: 1,
            state: CacheEntryState::Ready,
            load_time: 0,
        }
    }

    pub fn with_load_time(mut self, time: u64) -> Self {
        self.load_time = time;
        self
    }

    pub fn acquire(&mut self) {
        self.ref_count += 1;
    }

    pub fn release(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }

    pub fn is_referenced(&self) -> bool {
        self.ref_count > 0
    }

    pub fn base_addr(&self) -> VirtAddr {
        self.image.base_addr
    }

    pub fn entry_point(&self) -> VirtAddr {
        self.image.entry_point
    }
}

pub struct ImageCache {
    images: BTreeMap<usize, CachedImage>,
    name_index: BTreeMap<String, usize>,
    addr_index: BTreeMap<u64, usize>,
    max_entries: usize,
}

impl ImageCache {
    pub fn new() -> Self {
        Self::with_capacity(256)
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            images: BTreeMap::new(),
            name_index: BTreeMap::new(),
            addr_index: BTreeMap::new(),
            max_entries,
        }
    }

    pub fn insert(&mut self, name: String, image: ElfImage) -> ElfResult<usize> {
        if self.name_index.contains_key(&name) {
            return Err(ElfError::LibraryAlreadyLoaded);
        }

        if self.images.len() >= self.max_entries {
            self.evict_unreferenced()?;
        }

        let cached = CachedImage::new(name.clone(), image);
        let id = cached.id;
        let base_addr = cached.base_addr().as_u64();

        self.name_index.insert(name, id);
        self.addr_index.insert(base_addr, id);
        self.images.insert(id, cached);

        Ok(id)
    }

    pub fn get(&self, id: usize) -> Option<&CachedImage> {
        self.images.get(&id)
    }

    pub fn get_mut(&mut self, id: usize) -> Option<&mut CachedImage> {
        self.images.get_mut(&id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&CachedImage> {
        self.name_index.get(name).and_then(|id| self.images.get(id))
    }

    pub fn get_by_name_mut(&mut self, name: &str) -> Option<&mut CachedImage> {
        if let Some(&id) = self.name_index.get(name) {
            self.images.get_mut(&id)
        } else {
            None
        }
    }

    pub fn get_by_addr(&self, addr: VirtAddr) -> Option<&CachedImage> {
        self.addr_index.get(&addr.as_u64()).and_then(|id| self.images.get(id))
    }

    pub fn acquire(&mut self, id: usize) -> ElfResult<()> {
        self.images.get_mut(&id).ok_or(ElfError::LibraryNotFound)?.acquire();
        Ok(())
    }

    pub fn acquire_by_name(&mut self, name: &str) -> ElfResult<usize> {
        let id = *self.name_index.get(name).ok_or(ElfError::LibraryNotFound)?;
        self.images.get_mut(&id).ok_or(ElfError::LibraryNotFound)?.acquire();
        Ok(id)
    }

    pub fn release(&mut self, id: usize) -> ElfResult<bool> {
        let cached = self.images.get_mut(&id).ok_or(ElfError::LibraryNotFound)?;
        Ok(cached.release())
    }

    pub fn remove(&mut self, id: usize) -> ElfResult<CachedImage> {
        let cached = self.images.remove(&id).ok_or(ElfError::LibraryNotFound)?;

        self.name_index.remove(&cached.name);
        self.addr_index.remove(&cached.base_addr().as_u64());

        Ok(cached)
    }

    pub fn remove_if_unreferenced(&mut self, id: usize) -> ElfResult<Option<CachedImage>> {
        if let Some(cached) = self.images.get(&id) {
            if !cached.is_referenced() {
                return self.remove(id).map(Some);
            }
        }
        Ok(None)
    }

    fn evict_unreferenced(&mut self) -> ElfResult<()> {
        let unreferenced: Vec<usize> =
            self.images.iter().filter(|(_, c)| !c.is_referenced()).map(|(&id, _)| id).collect();

        if unreferenced.is_empty() {
            return Err(ElfError::CacheFull);
        }

        for id in unreferenced.iter().take(1) {
            self.remove(*id)?;
        }

        Ok(())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.name_index.contains_key(name)
    }

    pub fn contains_addr(&self, addr: VirtAddr) -> bool {
        self.addr_index.contains_key(&addr.as_u64())
    }

    pub fn count(&self) -> usize {
        self.images.len()
    }

    pub fn referenced_count(&self) -> usize {
        self.images.values().filter(|c| c.is_referenced()).count()
    }

    pub fn unreferenced_count(&self) -> usize {
        self.images.values().filter(|c| !c.is_referenced()).count()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CachedImage> {
        self.images.values()
    }

    pub fn clear_unreferenced(&mut self) -> usize {
        let unreferenced: Vec<usize> =
            self.images.iter().filter(|(_, c)| !c.is_referenced()).map(|(&id, _)| id).collect();

        let count = unreferenced.len();

        for id in unreferenced {
            let _ = self.remove(id);
        }

        count
    }

    pub fn clear(&mut self) {
        self.images.clear();
        self.name_index.clear();
        self.addr_index.clear();
    }
}

impl Default for ImageCache {
    fn default() -> Self {
        Self::new()
    }
}
