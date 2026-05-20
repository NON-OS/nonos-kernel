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

use crate::term::dimensions::{COLS, HISTORY_DEPTH};

pub struct History {
    pub(super) entries: [[u8; COLS]; HISTORY_DEPTH],
    pub(super) lengths: [usize; HISTORY_DEPTH],
    pub(super) count: usize,
    pub(super) cursor: Option<usize>,
}
