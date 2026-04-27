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

use super::super::super::dma::DmaRegion;
use super::super::super::types::CompletionEntry;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU16;

pub struct CompletionQueue {
    pub(super) region: DmaRegion,
    pub(super) entries: NonNull<CompletionEntry>,
    pub(super) depth: u16,
    pub(super) head: AtomicU16,
    pub(super) phase: AtomicU16,
    pub(super) doorbell_addr: usize,
    pub(super) qid: u16,
}

unsafe impl Send for CompletionQueue {}
unsafe impl Sync for CompletionQueue {}
