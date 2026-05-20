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

use nonos_libc::{mk_ipc_call, mk_service_lookup};

use crate::command::output::Output;
use crate::command::wire::{encode_healthcheck_header, HDR_LEN};
use crate::term::util::{copy_into, format_u64};

pub fn run(out: &mut Output<'_>, argv: &[&[u8]]) {
    if argv.len() < 2 {
        out.writeln(b"usage: ping <service>");
        return;
    }
    let name = argv[1];
    let mut port = 0u32;
    let mut pid = 0u32;
    let rc = mk_service_lookup(name.as_ptr(), name.len(), &mut port, &mut pid);
    if rc != 0 || port == 0 {
        out.writeln(b"  service not registered");
        return;
    }
    let mut req = [0u8; HDR_LEN];
    encode_healthcheck_header(&mut req);
    let mut rsp = [0u8; 64];
    let n = mk_ipc_call(port as u64, req.as_ptr(), req.len(), rsp.as_mut_ptr(), rsp.len());
    let mut line = [0u8; 64];
    let mut k = 0;
    if n < 0 {
        k += copy_into(&mut line[k..], b"  call failed errno=");
        k += format_u64((-n) as u64, &mut line[k..]);
    } else {
        k += copy_into(&mut line[k..], b"  ok rsp_bytes=");
        k += format_u64(n as u64, &mut line[k..]);
    }
    out.writeln(&line[..k]);
}
