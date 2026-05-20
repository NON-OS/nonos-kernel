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

use nonos_libc::{mk_service_lookup, mk_yield};

const COMPOSITOR_SERVICE: &[u8] = b"compositor";

fn lookup_port(name: &[u8]) -> Result<u32, &'static str> {
    let mut pid: u32 = 0;
    let mut port: u32 = 0;
    let rc =
        mk_service_lookup(name.as_ptr(), name.len(), &mut port as *mut u32, &mut pid as *mut u32);
    if rc < 0 || pid == 0 || port == 0 {
        return Err("service not announced");
    }
    Ok(port)
}

pub fn lookup_compositor_port() -> Result<u32, &'static str> {
    for _ in 0..256 {
        if let Ok(port) = lookup_port(COMPOSITOR_SERVICE) {
            return Ok(port);
        }
        mk_yield();
    }
    Err("compositor service not announced")
}
