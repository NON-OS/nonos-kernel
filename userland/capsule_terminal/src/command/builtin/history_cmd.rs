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

use crate::command::output::Output;
use crate::term::dimensions::{COLS, HISTORY_DEPTH};
use crate::term::history::History;
use crate::term::util::format_u64;

pub fn run(out: &mut Output<'_>, history: &mut History, _argv: &[&[u8]]) {
    let mut entries: [[u8; COLS]; HISTORY_DEPTH] = [[0; COLS]; HISTORY_DEPTH];
    let mut lengths = [0usize; HISTORY_DEPTH];
    let mut count = 0usize;
    while let Some(line) = history.prev() {
        if count == HISTORY_DEPTH {
            break;
        }
        let n = line.len().min(COLS);
        entries[count][..n].copy_from_slice(&line[..n]);
        lengths[count] = n;
        count += 1;
    }
    history.reset_cursor();
    for i in (0..count).rev() {
        let mut numbuf = [0u8; 4];
        let nn = format_u64((count - 1 - i) as u64, &mut numbuf);
        let p = nn.min(3);
        let mut line = [0u8; COLS];
        let mut o = 0;
        for k in 0..p {
            line[o] = numbuf[nn - p + k];
            o += 1;
        }
        line[o] = b':';
        line[o + 1] = b' ';
        o += 2;
        let body = &entries[i][..lengths[i]];
        let take = body.len().min(COLS - o);
        line[o..o + take].copy_from_slice(&body[..take]);
        out.writeln(&line[..o + take]);
    }
}
