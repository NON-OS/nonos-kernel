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

use nonos_libc::mk_service_lookup;

use crate::command::output::Output;
use crate::term::util::{copy_into, format_u64};

pub fn run(out: &mut Output<'_>, argv: &[&[u8]]) {
    if argv.len() < 2 {
        out.writeln(b"usage: service <name>");
        return;
    }
    let name = argv[1];
    let mut port = 0u32;
    let mut pid = 0u32;
    let rc = mk_service_lookup(name.as_ptr(), name.len(), &mut port, &mut pid);
    if rc != 0 || port == 0 {
        out.writeln(b"  not registered");
        return;
    }
    let mut line = [0u8; 64];
    let mut n = 0;
    n += copy_into(&mut line[n..], b"  port=");
    n += format_u64(port as u64, &mut line[n..]);
    n += copy_into(&mut line[n..], b"  pid=");
    n += format_u64(pid as u64, &mut line[n..]);
    out.writeln(&line[..n]);
}
