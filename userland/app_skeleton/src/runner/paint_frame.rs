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

use crate::app::{App, AppManifest};
use crate::paint::PaintBuffer;
use crate::setup::WindowBinding;

pub(super) fn paint<A: App>(app: &mut A, manifest: &AppManifest, binding: &WindowBinding) {
    let words = (binding.byte_len / 4) as usize;
    // SAFETY: backing_va is the surface the kernel mapped writable into our AS at register time; words = byte_len / 4.
    let pixels: &mut [u32] =
        unsafe { core::slice::from_raw_parts_mut(binding.backing_va as *mut u32, words) };
    let mut fb = PaintBuffer {
        pixels,
        stride_words: binding.stride_words,
        width: manifest.width,
        height: manifest.height,
    };
    app.paint(&mut fb);
}
