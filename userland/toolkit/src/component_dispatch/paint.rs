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

//! Paint a component into the attached surface buffer. Uses the
//! shared toolkit theme snapshot for colours and routes Button and
//! Label requests through the existing `components::{button,label}`
//! renderers.

use nonos_libc::SurfaceDescriptor;

use crate::components::button::{render_button, ButtonStyle};
use crate::components::label::{render_label, LabelStyle};
use crate::design::color::Argb;
use crate::theme;

use super::kind::ComponentKind;

pub fn paint(
    desc: &SurfaceDescriptor,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    kind: ComponentKind,
    label: &[u8],
) {
    let stride_px = (desc.stride as usize) / 4;
    let total = stride_px.saturating_mul(desc.height as usize);
    let buf: &mut [u32] =
        unsafe { core::slice::from_raw_parts_mut(desc.base_va as *mut u32, total) };
    let t = theme::snapshot();
    match kind {
        ComponentKind::Panel => {
            fill_rect(buf, stride_px, desc.width, desc.height, x, y, w, h, t.surface_argb);
        }
        ComponentKind::Button => {
            let style = ButtonStyle { bg: Argb(t.accent_argb), fg: Argb(t.text_argb) };
            render_button(buf, stride_px, desc.width, desc.height, x, y, w, h, label, style);
        }
        ComponentKind::Label => {
            let style = LabelStyle { color: Argb(t.text_argb) };
            render_label(buf, stride_px, desc.width, desc.height, x, y, label, style);
        }
    }
}

fn fill_rect(
    buf: &mut [u32],
    stride: usize,
    fb_w: u32,
    fb_h: u32,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    color: u32,
) {
    let x0 = x.min(fb_w) as usize;
    let y0 = y.min(fb_h) as usize;
    let x1 = (x.saturating_add(w)).min(fb_w) as usize;
    let y1 = (y.saturating_add(h)).min(fb_h) as usize;
    let mut py = y0;
    while py < y1 {
        let row = py.saturating_mul(stride);
        let mut px = x0;
        while px < x1 {
            let i = row.saturating_add(px);
            if i < buf.len() {
                buf[i] = color;
            }
            px += 1;
        }
        py += 1;
    }
}
