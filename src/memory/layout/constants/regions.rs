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

// Canonical kernel virtual layout.
//
// The directmap lives at PML4[256] (0xFFFF_8000_0000_0000), the
// lowest canonical kernel-half address. A 256-GiB linear window
// fits inside PML4[256]'s 512-GiB span, covers any production RAM
// target, and never overflows when a u64 phys is added to the
// base (the prior 0xFFFF_FFFF_B000_0000 base wrapped for any phys
// >= 0x5000_0000, silently producing low-half addresses).
//
// Heap (PML4[510]) and the KVM ad-hoc window (also PML4[510]) keep
// their existing bases so call sites that hardcode them stay
// valid.

pub const DIRECTMAP_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const DIRECTMAP_SIZE: u64 = 0x0000_0040_0000_0000;

pub const KHEAP_BASE: u64 = 0xFFFF_FF00_0000_0000;
pub const KHEAP_SIZE: u64 = 0x0000_0000_1000_0000;
pub const KVM_BASE: u64 = 0xFFFF_FF10_0000_0000;
pub const KVM_SIZE: u64 = 0x0000_0000_2000_0000;
