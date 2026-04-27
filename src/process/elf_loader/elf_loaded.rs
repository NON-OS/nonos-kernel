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

use super::types::LoadedSegment;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct LoadedElf {
    pub entry: u64,
    pub base_addr: u64,
    pub phdr_addr: u64,
    pub phnum: u16,
    pub phentsize: u16,
    pub segments: Vec<LoadedSegment>,
    pub interp: Option<String>,
    pub exec_stack: bool,
    pub min_addr: u64,
    pub max_addr: u64,
    pub tls_addr: u64,
    pub tls_size: u64,
    pub tls_align: u64,
}

impl LoadedElf {
    pub fn new(entry: u64, base_addr: u64, phnum: u16, phentsize: u16) -> Self {
        Self {
            entry,
            base_addr,
            phdr_addr: 0,
            phnum,
            phentsize,
            segments: Vec::new(),
            interp: None,
            exec_stack: false,
            min_addr: u64::MAX,
            max_addr: 0,
            tls_addr: 0,
            tls_size: 0,
            tls_align: 0,
        }
    }
    pub fn memory_size(&self) -> u64 {
        self.max_addr.saturating_sub(self.min_addr)
    }
    pub fn has_tls(&self) -> bool {
        self.tls_size > 0
    }
    pub fn get_tls_config(&self) -> (u64, u64, u64) {
        (self.tls_addr, self.tls_size, self.tls_align)
    }
    pub fn needs_interp(&self) -> bool {
        self.interp.is_some()
    }
    pub fn get_interp(&self) -> Option<&str> {
        self.interp.as_deref()
    }
    pub fn allows_exec_stack(&self) -> bool {
        self.exec_stack
    }
    pub fn get_phdr_info(&self) -> (u64, u16, u16) {
        (self.phdr_addr, self.phnum, self.phentsize)
    }
}
