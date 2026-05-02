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

use super::backend;

/// Drain prior MMIO writes — including any sitting in a write-combining
/// buffer — before subsequent writes proceed.
#[inline]
pub fn fence_writes() {
    backend::fence_writes();
}

/// Make subsequent MMIO reads observe state ordered after every prior
/// read at the hardware level.
#[inline]
pub fn fence_reads() {
    backend::fence_reads();
}

/// Order all prior loads and stores against all subsequent loads and
/// stores, across MMIO and write-back cacheable memory both. The only
/// fence that guarantees StoreLoad ordering on mixed mappings.
#[inline]
pub fn fence_full() {
    backend::fence_full();
}
