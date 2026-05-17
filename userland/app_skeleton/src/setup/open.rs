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

use crate::app::AppManifest;
use crate::discover::Peers;

use super::announce::announce;
use super::backing::alloc_backing;
use super::binding::WindowBinding;
use super::register::register_and_share;

pub fn open_window(
    peers: &Peers,
    manifest: &AppManifest,
    request_id: &mut u32,
) -> Result<WindowBinding, &'static str> {
    let (backing_va, stride, byte_len) = alloc_backing(manifest.width, manifest.height)?;
    let surface_handle = register_and_share(backing_va, manifest.width, manifest.height, stride, byte_len)?;
    announce(peers, manifest, surface_handle, request_id)?;
    Ok(WindowBinding { surface_handle, backing_va, stride_words: manifest.width, byte_len })
}
