// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::*;
#[derive(Clone, Copy, Debug)]
pub struct LayoutConfig {
    pub slide: u64,
    pub heap_lo: u64,
    pub heap_sz: u64,
    pub vm_lo: u64,
    pub vm_sz: u64,
    pub mmio_lo: u64,
    pub mmio_sz: u64,
    pub initialized: bool,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            slide: 0,
            heap_lo: KHEAP_BASE,
            heap_sz: KHEAP_SIZE,
            vm_lo: KVM_BASE,
            vm_sz: KVM_SIZE,
            mmio_lo: MMIO_BASE,
            mmio_sz: MMIO_SIZE,
            initialized: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub start: u64,
    pub end: u64,
    pub rx: bool,
    pub rw: bool,
    pub nx: bool,
    pub global: bool,
}

impl Section {
    pub const fn new(start: u64, end: u64, rx: bool, rw: bool, nx: bool, global: bool) -> Self {
        Self { start, end, rx, rw, nx, global }
    }

    #[inline]
    pub const fn size(&self) -> u64 {
        if self.end > self.start { self.end - self.start } else { 0 }
    }

    #[inline]
    pub const fn page_count(&self) -> u64 {
        (self.size() + PAGE_SIZE_U64 - 1) / PAGE_SIZE_U64
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    Available,
    Usable,
    Reserved,
    Acpi,
    Mmio,
    Kernel,
    Boot,
    Unknown,
}

impl RegionKind {
    #[inline]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Usable | Self::Available)
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Usable => "Usable",
            Self::Reserved => "Reserved",
            Self::Acpi => "ACPI",
            Self::Mmio => "MMIO",
            Self::Kernel => "Kernel",
            Self::Boot => "Boot",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub kind: RegionKind,
}

impl Region {
    pub const fn new(start: u64, end: u64, kind: RegionKind) -> Self {
        Self { start, end, kind }
    }

    #[inline]
    pub const fn len(&self) -> u64 {
        if self.end > self.start { self.end - self.start } else { 0 }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    #[inline]
    pub const fn is_usable(&self) -> bool {
        self.kind.is_usable()
    }

    #[inline]
    pub const fn start_addr(&self) -> u64 { self.start }

    #[inline]
    pub const fn end_addr(&self) -> u64 { self.end }

    #[inline]
    pub const fn page_count(&self) -> u64 {
        self.len() / PAGE_SIZE_U64
    }

    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackRegion {
    pub base: u64,
    pub size: usize,
    pub guard_size: usize,
    pub cpu_id: Option<u32>,
    pub thread_id: Option<u64>,
}

impl StackRegion {
    pub const fn new(base: u64, size: usize, guard_size: usize) -> Self {
        Self { base, size, guard_size, cpu_id: None, thread_id: None }
    }

    pub const fn per_cpu(base: u64, size: usize, guard_size: usize, cpu_id: u32) -> Self {
        Self { base, size, guard_size, cpu_id: Some(cpu_id), thread_id: None }
    }

    #[inline]
    pub const fn total_size(&self) -> usize {
        self.size + self.guard_size
    }

    #[inline]
    pub const fn stack_top(&self) -> u64 {
        self.base + self.size as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PercpuRegion {
    pub base: u64,
    pub size: usize,
    pub cpu_id: u32,
}

impl PercpuRegion {
    pub const fn new(base: u64, size: usize, cpu_id: u32) -> Self {
        Self { base, size, cpu_id }
    }

    #[inline]
    pub const fn end(&self) -> u64 {
        self.base + self.size as u64
    }

    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRegion {
    pub base: u64,
    pub size: usize,
    pub name: &'static str,
    pub permissions: u32,
}

impl ModuleRegion {
    pub const fn new(base: u64, size: usize, name: &'static str, permissions: u32) -> Self {
        Self { base, size, name, permissions }
    }

    #[inline]
    pub const fn is_readable(&self) -> bool {
        (self.permissions & PERM_READ) != 0
    }

    #[inline]
    pub const fn is_writable(&self) -> bool {
        (self.permissions & PERM_WRITE) != 0
    }

    #[inline]
    pub const fn is_executable(&self) -> bool {
        (self.permissions & PERM_EXEC) != 0
    }

    #[inline]
    pub const fn end(&self) -> u64 {
        self.base + self.size as u64
    }
}
