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

// Cross-architecture memory map handle.
//
// `map_ptr` and `map_entries` describe an array of memory descriptors
// supplied by the bootloader. The entry layout is arch-specific
// (UEFI memory descriptors on x86_64; per-arch device-tree-derived
// regions on aarch64/riscv64). The kernel core only needs the
// summarized `largest_usable_bytes` field to route the canonical
// physical-memory init.
//
// Per-arch code that needs to walk the full map reads the matching
// variant of `ArchSpecificHandoff`, which carries the typed handle.

#[derive(Debug, Clone, Copy)]
pub struct MemoryHandoff {
    pub map_ptr: u64,
    pub map_entries: u32,
    pub largest_usable_bytes: u64,
}
