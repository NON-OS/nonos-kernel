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

use core::sync::atomic::{AtomicU64, Ordering};

pub(super) static SEQUENCES_PARSED: AtomicU64 = AtomicU64::new(0);
pub(super) static SEQUENCES_IGNORED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParserState {
    Normal,
    Escape,
    Csi,
    DecPrivate,
}

impl Default for ParserState {
    fn default() -> Self {
        ParserState::Normal
    }
}

pub(super) fn inc_parsed() {
    SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
}
pub(super) fn inc_ignored() {
    SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
}
