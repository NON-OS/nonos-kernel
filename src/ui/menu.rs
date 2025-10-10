// src/ui/menu.rs
#![allow(clippy::identity_op)]

use crate::gfx::{Fb};
use crate::ui::keyboard::{Key, KeyEvent};

pub struct Menu<'a> {
    pub title: &'a str,
    pub items: &'a [&'a str],
    pub selected: usize,
    dirty: bool,
}

impl<'a> Menu<'a> {
    pub const fn new(title: &'a str, items: &'a [&'a str]) -> Self {
        Self { title, items, selected: 0, dirty: true }
    }

    /// Handle a key event; returns Some(index) on Enter.
    pub fn handle(&mut self, ev: KeyEvent) -> Option<usize> {
        match ev.key {
            Key::Up => {
                if self.selected == 0 { self.selected = self.items.len().saturating_sub(1); }
                else { self.selected -= 1; }
                self.dirty = true;
                None
            }
            Key::Down => {
                let n = self.items.len().max(1);
                self.selected = (self.selected + 1) % n;
                self.dirty = true;
                None
            }
            Key::Enter => Some(self.selected),
            _ => None,
        }
    }

    /// Draw only if dirty (to avoid flicker). Force with force=true.
    pub unsafe fn draw(&mut self, fb: &Fb, force: bool) {
        if !self.dirty && !force { return; }
        self.dirty = false;

        let (w, h) = (fb.w as i32, fb.h as i32);

        // Backdrop
        fill_rect(fb, 0, 0, w, h, pack32(fb.fmt, 8, 12, 18));

        // Panel
        let panel_w: i32 = (w * 3) / 5;
        let panel_h: i32 = (h * 2) / 5;
        let px: i32 = w / 2 - panel_w / 2;
        let py: i32 = h / 2 - panel_h / 2;

        fill_rounded_rect(fb, px, py, panel_w, panel_h, 12, pack32(fb.fmt, 18, 26, 38));
        for ii in 0..2_i32 {
            fill_rounded_rect(
                fb,
                px + ii,
                py + ii,
                panel_w - 2 * ii,
                panel_h - 2 * ii,
                10,
                pack32(fb.fmt, 28, 44, 60),
            );
        }

        // Title
        let title_scale: i32 = (w.min(h) / 100).clamp(2, 5);
        let title_w: i32 = (self.title.len() as i32) * 8 * title_scale;
        let tx: i32 = w / 2 - title_w / 2;
        let ty: i32 = py + 16;
        draw_text_scaled(fb, self.title.as_bytes(), tx + 1, ty, title_scale, pack32(fb.fmt, 40, 190, 230));
        draw_text_scaled(fb, self.title.as_bytes(), tx,     ty, title_scale, pack32(fb.fmt, 180, 235, 255));

        // Items
        let item_scale: i32 = title_scale;
        let line_h: i32 = 18 * item_scale;
        let mut y: i32 = ty + 24 + item_scale * 8;

        for (i, it) in self.items.iter().enumerate() {
            let iw: i32 = (it.len() as i32) * 8 * item_scale;
            let ix: i32 = w / 2 - iw / 2;

            if i == self.selected {
                fill_rounded_rect(fb, ix - 12, y - 6, iw + 24, 16 * item_scale + 12, 8, pack32(fb.fmt, 24, 60, 80));
                draw_text_scaled(fb, it.as_bytes(), ix + 1, y, item_scale, pack32(fb.fmt,  20, 220, 255));
                draw_text_scaled(fb, it.as_bytes(), ix,     y, item_scale, pack32(fb.fmt, 230, 245, 255));
            } else {
                draw_text_scaled(fb, it.as_bytes(), ix, y, item_scale, pack32(fb.fmt, 200, 220, 235));
            }
            y += line_h;
        }
    }
}

// ===== local helpers (integer-only drawing / text) =====

use core::ptr;

#[inline]
fn pack32(fmt: u16, r: u8, g: u8, b: u8) -> u32 {
    if fmt == 1 { ((r as u32) << 16) | ((g as u32) << 8) | (b as u32) }
    else        { ((b as u32) << 16) | ((g as u32) << 8) | (r as u32) }
}

#[inline]
unsafe fn put_px(fb: &Fb, x: i32, y: i32, c: u32) {
    if x < 0 || y < 0 { return; }
    let (xu, yu) = (x as u32, y as u32);
    if xu >= fb.w || yu >= fb.h { return; }
    let bpp = (fb.bpp as usize) / 8;
    let off = (yu as usize) * (fb.pitch as usize) + (xu as usize) * bpp;
    ptr::write_unaligned(fb.base.add(off) as *mut u32, c);
}

fn fill_rect(fb: &Fb, x0: i32, y0: i32, w: i32, h: i32, c: u32) {
    for yy in y0..(y0 + h) {
        for xx in x0..(x0 + w) {
            unsafe { put_px(fb, xx, yy, c); }
        }
    }
}

fn fill_rounded_rect(fb: &Fb, x0: i32, y0: i32, w: i32, h: i32, r: i32, c: u32) {
    if h > 2 * r { fill_rect(fb, x0, y0 + r, w, h - 2 * r, c); }
    for dy in 0..r {
        let dx = circle_hspan(r, dy);
        let left  = x0 + r - dx;
        let right = x0 + w - r + dx - 1;
        let y_top = y0 + dy;
        let y_bot = y0 + h - 1 - dy;
        for xx in left..=right {
            unsafe { put_px(fb, xx, y_top, c); }
            unsafe { put_px(fb, xx, y_bot, c); }
        }
    }
}

fn circle_hspan(r: i32, y: i32) -> i32 {
    let y2 = (y * y) as i64;
    let r2 = (r * r) as i64;
    let mut x = r as i64;
    while x * x + y2 > r2 { x -= 1; }
    x as i32
}

fn glyph8x16(ch: u8) -> [u8; 16] {
    match ch {
        b' ' => [0;16],
        b'A' => [0x18,0x3C,0x66,0x66,0x7E,0x7E,0x66,0x66,0x66,0x66,0x00,0,0,0,0,0],
        b'E' => [0x7E,0x7E,0x60,0x60,0x7C,0x7C,0x60,0x60,0x60,0x7E,0x00,0,0,0,0,0],
        b'I' => [0x7E,0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0,0,0,0,0],
        b'N' => [0x63,0x73,0x7B,0x6F,0x67,0x63,0x63,0x63,0x63,0x63,0x00,0,0,0,0,0],
        b'O' => [0x3C,0x7E,0xE7,0xC3,0xC3,0xC3,0xC3,0xC3,0xE7,0x7E,0x00,0,0,0,0,0],
        b'R' => [0x7C,0x7E,0x63,0x63,0x7E,0x7C,0x6C,0x66,0x63,0x63,0x00,0,0,0,0,0],
        b'S' => [0x3E,0x7F,0x61,0x60,0x7C,0x3E,0x07,0x03,0x63,0x7F,0x00,0,0,0,0,0],
        b'T' => [0x7E,0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0,0,0,0,0],
        b'U' => [0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x7F,0x3E,0x00,0,0,0,0,0],
        b'0' => [0x3C,0x7E,0xE7,0xC3,0xCB,0xDB,0xD3,0xC3,0xE7,0x7E,0x00,0,0,0,0,0],
        b'1' => [0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x18,0x7E,0x7E,0x00,0,0,0,0,0],
        b'-' => [0x00,0x00,0x00,0x00,0x3C,0x3C,0x00,0x00,0x00,0x00,0,0,0,0,0,0],
        b'.' => [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0,0,0,0,0,0],
        _    => [0;16],
    }
}

fn draw_glyph_scaled(fb: &Fb, ch: u8, x0: i32, y0: i32, scale: i32, color: u32) {
    let g = glyph8x16(ch);
    for row in 0..16 {
        let bits = g[row as usize];
        for col in 0..8 {
            if (bits & (1 << (7 - col))) != 0 {
                for dy in 0..scale {
                    for dx in 0..scale {
                        unsafe { put_px(fb, x0 + col * scale + dx, y0 + row * scale + dy, color); }
                    }
                }
            }
        }
    }
}

fn draw_text_scaled(fb: &Fb, s: &[u8], mut x: i32, y: i32, scale: i32, color: u32) {
    for &ch in s {
        draw_glyph_scaled(fb, ch, x, y, scale, color);
        x += 8 * scale + 2; // a little letter spacing
    }
}
