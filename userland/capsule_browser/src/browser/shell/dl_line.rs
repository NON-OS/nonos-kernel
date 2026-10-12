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

use alloc::format;
use alloc::string::String;

use super::downloads::{counts, human_bytes};
use super::types::{DlState, Download};

/// How this session's downloads stand, for the start page: how many were
/// saved and how many failed.
pub fn count_line(list: &[Download]) -> String {
    match counts(list) {
        [0, _, _] => String::from("Downloads: none yet"),
        [_, saved, 0] => format!("Downloads: {} saved", saved),
        [_, saved, failed] => format!("Downloads: {} saved, {} failed", saved, failed),
    }
}

/// One download as a line: the file it is being or was saved as, with its
/// size once saved, or why it was not.
pub fn status_line(d: &Download) -> String {
    match &d.state {
        DlState::Saving => format!("Saving {}", d.name),
        DlState::Saved => format!("Saved {} ({})", d.name, human_bytes(d.bytes)),
        DlState::Failed(why) => format!("{} not saved: {}", d.name, why),
    }
}
