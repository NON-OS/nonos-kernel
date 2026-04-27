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

use super::super::completion::CompletionQueue;
use super::super::submission::SubmissionQueue;
use core::sync::atomic::{AtomicU16, AtomicU32};

pub struct QueuePair {
    pub(super) sq: SubmissionQueue,
    pub(super) cq: CompletionQueue,
    pub(super) timeout_spins: AtomicU32,
    pub(super) pending_commands: AtomicU16,
}

unsafe impl Send for QueuePair {}
unsafe impl Sync for QueuePair {}
