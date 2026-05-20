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

use nonos_libc::nonos_display_dimensions;

use crate::command::output::Output;
use crate::term::util::{copy_into, format_u64};

pub fn run(out: &mut Output<'_>, _argv: &[&[u8]]) {
    let mut width = 0u32;
    let mut height = 0u32;
    let rc = nonos_display_dimensions(0, &mut width, &mut height);
    let mut line = [0u8; 64];
    let mut n = 0;
    if rc < 0 {
        n += copy_into(&mut line[n..], b"  display query failed errno=");
        n += format_u64((-rc) as u64, &mut line[n..]);
    } else {
        n += copy_into(&mut line[n..], b"  primary: ");
        n += format_u64(width as u64, &mut line[n..]);
        n += copy_into(&mut line[n..], b" x ");
        n += format_u64(height as u64, &mut line[n..]);
        n += copy_into(&mut line[n..], b"  format=ARGB8888");
    }
    out.writeln(&line[..n]);
}
