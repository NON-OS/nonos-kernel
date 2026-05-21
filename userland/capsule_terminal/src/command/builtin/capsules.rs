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

const EXPECTED: &[&[u8]] = &[
    b"ramfs",
    b"vfs",
    b"keyring",
    b"entropy",
    b"crypto",
    b"market",
    b"driver.virtio_rng",
    b"driver.virtio_blk",
    b"driver.virtio_gpu",
    b"driver.virtio_net",
    b"driver.ps2_input",
    b"driver.xhci",
    b"compositor",
    b"wm",
    b"desktop_shell",
    b"input_router",
    b"net.l2",
    b"net.ip",
    b"net.udp",
    b"net.dhcp",
    b"login",
    b"wallpaper",
];

pub fn run(out: &mut Output<'_>, _argv: &[&[u8]]) {
    for name in EXPECTED {
        let mut port = 0u32;
        let mut pid = 0u32;
        let rc = mk_service_lookup(name.as_ptr(), name.len(), &mut port, &mut pid);
        let alive = rc == 0 && port != 0;
        let mut line = [0u8; 96];
        let mut n = 0;
        n += copy_into(&mut line[n..], if alive { b"[live]   " } else { b"[absent] " });
        n += copy_into(&mut line[n..], name);
        if alive {
            n += copy_into(&mut line[n..], b"  pid=");
            n += format_u64(pid as u64, &mut line[n..]);
        }
        out.writeln(&line[..n]);
    }
}
