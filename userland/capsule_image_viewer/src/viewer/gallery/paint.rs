extern crate alloc;
use crate::viewer::gallery::layout::{cell_rect, grid, Grid, HEADER_H, THUMB_H, THUMB_W};
use crate::viewer::gallery::state::GalleryState;
use crate::viewer::says::{gallery_next, gallery_note};
use crate::viewer::scale::{draw_nn, Dst};
use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::mix;
use nonos_toolkit::theme::roles;

/// The bitmap face's advance, for centring a line by its length.
const GLYPH_W: u32 = 8;

pub fn paint_gallery(g: &mut GalleryState, fb: &mut PaintBuffer) {
    let (w, h, r) = (fb.width, fb.height, roles());
    let text = r.text.argb();
    fb.fill_rect(0, 0, w, h, r.bg.argb());
    let gr = grid(w);
    let n = g.entries.len();
    if let Some(note) = gallery_note(g.scanned, g.scan_error, n) {
        let x = (w / 2).saturating_sub(note.len() as u32 * GLYPH_W / 2);
        fb.text(x, h / 2, note.as_bytes(), text);
        if let Some(next) = gallery_next(g.scanned, g.scan_error, n) {
            let x = (w / 2).saturating_sub(next.len() as u32 * GLYPH_W / 2);
            fb.text(x, h / 2 + 2 * GLYPH_W, next.as_bytes(), r.muted.argb());
        }
        return;
    }
    paint_boxes(fb, g, &gr, n);
    blit_thumbs(fb, g, &gr, n);
    fb.text(10, 8, b"Gallery", text);
    if let Some(trouble) = g.decoder_trouble {
        fb.text(10 + 9 * GLYPH_W, 8, trouble.as_bytes(), r.danger.argb());
    }
}

fn paint_boxes(fb: &mut PaintBuffer, g: &GalleryState, gr: &Grid, n: usize) {
    let (h, r) = (fb.height, roles());
    for i in 0..n {
        let (x, y, _cw, ch) = cell_rect(i, g.scroll, gr);
        if y + ch as i32 <= HEADER_H as i32 || y >= h as i32 {
            continue;
        }
        let (ux, uy) = (x.max(0) as u32, y.max(0) as u32);
        let e = &g.entries[i];
        let base = if e.failed {
            mix(r.surface.argb(), r.danger.argb(), 40)
        } else if e.thumb.is_none() {
            r.surface.argb()
        } else {
            r.bg.argb()
        };
        fb.fill_rect(ux, uy, THUMB_W, THUMB_H, base);
        if i == g.sel {
            fb.fill_rect(ux, uy, THUMB_W, 2, r.accent.argb());
            fb.fill_rect(ux, uy + THUMB_H - 2, THUMB_W, 2, r.accent.argb());
        }
        fb.text(ux, uy + THUMB_H, label(&e.path), r.text.argb());
    }
}

fn blit_thumbs(fb: &mut PaintBuffer, g: &GalleryState, gr: &Grid, n: usize) {
    let (w, h, stride) = (fb.width, fb.height, fb.stride_words);
    let mut dst = Dst { px: fb.pixels, stride, w, h };
    for i in 0..n {
        let (x, y, _cw, ch) = cell_rect(i, g.scroll, gr);
        if y + ch as i32 <= HEADER_H as i32 || y >= h as i32 {
            continue;
        }
        if let Some(thumb) = g.entries[i].thumb.as_ref() {
            let (tw, th) = (g.entries[i].tw, g.entries[i].th);
            let ox = x + ((THUMB_W - tw) / 2) as i32;
            let oy = y + ((THUMB_H - th) / 2) as i32;
            draw_nn(&mut dst, thumb, tw, th, ox, oy, tw, th);
        }
    }
}

fn label(path: &str) -> &[u8] {
    let b = path.as_bytes();
    let start = match b.iter().rposition(|&c| c == b'/') {
        Some(i) => i + 1,
        None => 0,
    };
    let end = (start + 18).min(b.len());
    &b[start..end]
}
