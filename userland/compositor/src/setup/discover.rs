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

const GFX_SERVICE: &[u8] = b"driver.virtio_gpu0";

// Resolves the gfx driver's pid through the kernel service registry.
// Returns NotReady until the driver has announced itself, at which
// point we cache the pid for the lifetime of this compositor.
pub fn lookup_gfx_pid() -> Result<u32, &'static str> {
    let rc = mk_service_lookup(GFX_SERVICE.as_ptr(), GFX_SERVICE.len());
    if rc <= 0 {
        return Err("gfx service not announced");
    }
    Ok(rc as u32)
}
