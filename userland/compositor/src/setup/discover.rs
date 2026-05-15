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

pub struct GfxEndpoint {
    pub port: u32,
}

// Resolves the gfx driver's port through the kernel service registry.
// mk_ipc_call routes by port; the kernel verifies the owning pid is
// alive before delivery, so the compositor does not need to hold it.
pub fn lookup_gfx_endpoint() -> Result<GfxEndpoint, &'static str> {
    let mut pid: u32 = 0;
    let mut port: u32 = 0;
    let rc = mk_service_lookup(
        GFX_SERVICE.as_ptr(),
        GFX_SERVICE.len(),
        &mut port as *mut u32,
        &mut pid as *mut u32,
    );
    if rc < 0 || pid == 0 || port == 0 {
        return Err("gfx service not announced");
    }
    Ok(GfxEndpoint { port })
}
