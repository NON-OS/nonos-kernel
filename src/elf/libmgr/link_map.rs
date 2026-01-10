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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use x86_64::VirtAddr;

#[repr(C)]
pub struct LinkMapEntry {
    pub l_addr: u64,
    pub l_name: *const u8,
    pub l_ld: u64,
    pub l_next: *mut LinkMapEntry,
    pub l_prev: *mut LinkMapEntry,
}

impl LinkMapEntry {
    pub fn new(base_addr: u64, name_ptr: *const u8, dynamic_addr: u64) -> Self {
        Self {
            l_addr: base_addr,
            l_name: name_ptr,
            l_ld: dynamic_addr,
            l_next: ptr::null_mut(),
            l_prev: ptr::null_mut(),
        }
    }
}

pub struct LinkMap {
    entries: Vec<Box<LinkMapEntry>>,
    names: Vec<Vec<u8>>,
    head: *mut LinkMapEntry,
    tail: *mut LinkMapEntry,
}

impl LinkMap {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            names: Vec::new(),
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }

    pub fn add(
        &mut self,
        base_addr: VirtAddr,
        name: &str,
        dynamic_addr: VirtAddr,
    ) -> *mut LinkMapEntry {
        let mut name_bytes: Vec<u8> = name.bytes().collect();
        name_bytes.push(0);
        self.names.push(name_bytes);

        let name_ptr = self.names.last().unwrap().as_ptr();

        let mut entry =
            Box::new(LinkMapEntry::new(base_addr.as_u64(), name_ptr, dynamic_addr.as_u64()));

        let entry_ptr = entry.as_mut() as *mut LinkMapEntry;

        if self.head.is_null() {
            self.head = entry_ptr;
            self.tail = entry_ptr;
        } else {
            // SAFETY: tail is valid when head is not null
            unsafe {
                (*self.tail).l_next = entry_ptr;
                entry.l_prev = self.tail;
            }
            self.tail = entry_ptr;
        }

        self.entries.push(entry);
        entry_ptr
    }

    pub fn remove(&mut self, base_addr: VirtAddr) -> bool {
        let addr = base_addr.as_u64();
        let mut found_idx = None;

        for (i, entry) in self.entries.iter().enumerate() {
            if entry.l_addr == addr {
                found_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = found_idx {
            let entry = &self.entries[idx];
            let entry_ptr = entry.as_ref() as *const LinkMapEntry as *mut LinkMapEntry;

            // SAFETY: Pointers are valid within the link map
            unsafe {
                if !entry.l_prev.is_null() {
                    (*entry.l_prev).l_next = entry.l_next;
                } else {
                    self.head = entry.l_next;
                }

                if !entry.l_next.is_null() {
                    (*entry.l_next).l_prev = entry.l_prev;
                } else {
                    self.tail = entry.l_prev;
                }
            }

            self.entries.remove(idx);
            self.names.remove(idx);
            true
        } else {
            false
        }
    }

    pub fn find(&self, base_addr: VirtAddr) -> Option<&LinkMapEntry> {
        let addr = base_addr.as_u64();
        self.entries.iter().find(|e| e.l_addr == addr).map(|e| e.as_ref())
    }

    pub fn head(&self) -> *mut LinkMapEntry {
        self.head
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LinkMapEntry> {
        self.entries.iter().map(|e| e.as_ref())
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.names.clear();
        self.head = ptr::null_mut();
        self.tail = ptr::null_mut();
    }
}

impl Default for LinkMap {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: LinkMap is not Send/Sync by default due to raw pointers,
// but we manage the pointers carefully within the struct
unsafe impl Send for LinkMap {}
