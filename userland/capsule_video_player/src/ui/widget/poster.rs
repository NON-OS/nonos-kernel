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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::derive::mix;
use nonos_toolkit::theme::roles;

use crate::catalog::kind::MediaKind;
use crate::catalog::thumb::{THUMB_H, THUMB_W};
use crate::ui::icon;
use crate::ui::layout::Rect;
use crate::ui::paint::rrect;

const RADIUS: u32 = 10;
const MARK: u32 = 30;

/// A faint wash of one hue per container over the card, so the kinds tell
/// apart at a glance: accent, warn, a neutral step of the text, and ok.
fn tint(kind: MediaKind) -> u32 {
    let r = roles();
    let (card, hue, t) = match kind {
        MediaKind::Avi => (r.surface, r.accent, 40),
        MediaKind::Mp4 => (r.surface, r.warn, 40),
        MediaKind::Mkv => (r.surface, r.text, 24),
        MediaKind::Mov => (r.surface, r.ok, 40),
    };
    mix(card.argb(), hue.argb(), t)
}

/// The video's first frame when the probe decoded one (`catalog/thumb.rs`),
/// else a plain card with the video mark. The thumbnail was decoded for
/// every video at scan and never drawn.
pub fn paint_poster(fb: &mut PaintBuffer, r: Rect, kind: MediaKind, thumb: Option<&[u32]>) {
    let theme = roles();
    if let Some(pixels) = thumb {
        if paint_frame(fb, r, pixels, THUMB_W, THUMB_H) {
            rrect::stroke_round(fb, r.x, r.y, r.w, r.h, RADIUS, 1, theme.border.argb());
            return;
        }
    }
    rrect::fill_round(fb, r.x, r.y, r.w, r.h, RADIUS, tint(kind));
    rrect::stroke_round(fb, r.x, r.y, r.w, r.h, RADIUS, 1, theme.border.argb());
    let size = MARK.min(r.w / 3).min(r.h / 3).max(12);
    icon::nav::video(
        fb,
        r.x + r.w.saturating_sub(size) / 2,
        r.y + r.h.saturating_sub(size) / 2,
        size,
        theme.quiet.argb(),
    );
}

pub fn paint_frame(fb: &mut PaintBuffer, r: Rect, pixels: &[u32], sw: u32, sh: u32) -> bool {
    if sw == 0 || sh == 0 || pixels.len() < (sw as usize * sh as usize) {
        return false;
    }
    let stride = fb.stride_words as usize;
    for row in 0..r.h.min(fb.height.saturating_sub(r.y)) {
        let sy = (row as u64 * sh as u64 / r.h as u64) as u32;
        let base = (r.y + row) as usize * stride + r.x as usize;
        for col in 0..r.w.min(fb.width.saturating_sub(r.x)) {
            let sx = (col as u64 * sw as u64 / r.w as u64) as u32;
            fb.pixels[base + col as usize] = pixels[(sy * sw + sx) as usize];
        }
    }
    true
}
