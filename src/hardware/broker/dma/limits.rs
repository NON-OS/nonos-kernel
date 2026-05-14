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

//! Per-class DMA page ceiling. The broker refuses `MkDmaMap` requests
//! larger than the ceiling for the device's class. Caps are the
//! point at which a misbehaving capsule pays the cost of its own
//! over-request — a queue-sized NVMe SQ/CQ fits inside the block
//! ceiling, a virtio-rng descriptor ring does not need anywhere
//! near that. Anything not classified lands on the same conservative
//! ceiling that pre-existed this split.

use crate::hardware::broker::class::ids;

pub(super) const FALLBACK_PAGES: u64 = 16;

// Page caps. 4 KiB pages assumed (broker PAGE_SIZE).
pub(super) const fn dma_page_limit_for_class(class_id: u32) -> u64 {
    match class_id {
        ids::RNG => 1,
        ids::INPUT => 1,
        ids::SERIAL => 1,
        ids::AUDIO => 16,
        ids::NETWORK => 64,
        ids::USB_HOST => 256,
        ids::USB_HOST_XHCI => 256,
        ids::BLOCK => 1024,
        // Display surfaces are framebuffer-sized and capsule-mapped
        // through MMIO, not through MkDmaMap. Treat as fallback.
        ids::DISPLAY => FALLBACK_PAGES,
        _ => FALLBACK_PAGES,
    }
}
