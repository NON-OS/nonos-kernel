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

//! How an install's progress reads to a person, and in what tone.

use nonos_market_proto::reason;

use super::progress::Progress;
use crate::store::tone::{Tone, ACCENT, DANGER, MUTED, OK};

impl Progress {
    /// A sentence for the detail pane, with its tone, when there is news.
    pub fn sentence(self) -> Option<(&'static [u8], Tone)> {
        let line: (&'static [u8], Tone) = match self {
            Progress::Idle => return None,
            Progress::Queued => (b"Waiting for the installer to start", MUTED),
            Progress::Installing => (b"Downloading and checking every file", ACCENT),
            Progress::Installed => (b"Installed. Press Enter to open it", OK),
            Progress::Refused => {
                (b"The system would not start the installer; press Enter to ask again", DANGER)
            }
            Progress::Removing => (b"Taking away what its install put on this machine", ACCENT),
            Progress::Removed => (b"Uninstalled: what its install put here is gone", MUTED),
            /*
             * The reasons are the Terminal's too (`nonos_market_proto`). One
             * no retry can change, no NONOS disk above all, is a fact about the
             * machine rather than a fault, and is not painted red.
             */
            Progress::Failed(why) => {
                let said = reason(why);
                (said.line.as_bytes(), if said.retry { DANGER } else { MUTED })
            }
        };
        Some(line)
    }
}

/*
 * One installer runs at a time, so an install asked for while another moves
 * waits its turn (init's linux_jobs keeps it queued, in order). It says what
 * it waits for and how far that has got, never only "Queued": a person who
 * pressed Install twice and saw nothing happen pressed it six more times.
 */
/// The detail line for an install waiting behind `ahead`, a listing's name,
/// with `how` far that one has got when its download is being counted.
pub fn waiting_behind(ahead: &[u8], how: Option<&str>) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(96 + ahead.len());
    out.extend_from_slice(b"Waiting: ");
    out.extend_from_slice(ahead);
    out.extend_from_slice(b" installs first");
    if let Some(how) = how {
        out.extend_from_slice(b" (");
        out.extend_from_slice(how.as_bytes());
        out.push(b')');
    }
    out.extend_from_slice(b". This one starts when it ends.");
    out
}
