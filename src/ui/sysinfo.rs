#![allow(clippy::identity_op)]

use crate::gfx::Fb;
use crate::text::render::{draw_text, LayoutOpts, TextStyle};
use crate::text::TextCtx;

// --------- tiny integer-only blitters ---------
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

// --------- number formatting (no alloc) ---------
#[inline]
fn u32_to_str<'a>(buf: &'a mut [u8; 12], mut n: u32) -> &'a str {
    if n == 0 { return "0"; }
    let mut i = buf.len();
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}
#[inline]
fn u64_to_str<'a>(buf: &'a mut [u8; 21], mut n: u64) -> &'a str {
    if n == 0 { return "0"; }
    let mut i = buf.len();
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}
#[inline]
fn mib_str<'a>(buf: &'a mut [u8; 21], bytes: u64) -> &'a str {
    let mib = bytes / (1024 * 1024);
    u64_to_str(buf, mib)
}

// --------- simple text width ---------
#[inline]
fn measure_width(ctx: &mut TextCtx, s: &str, px: u16, mono: bool) -> i32 {
    let mut sum = 0i32;
    for ch in s.chars() {
        let g = ctx.raster_glyph(ch, px, mono);
        sum += g.advance as i32;
    }
    sum.max(0)
}

// --------- public API ---------
pub unsafe fn draw_system_info(ctx: &mut TextCtx, fb: &Fb, mem_bytes: Option<u64>) {
    let (w, h) = (fb.w as i32, fb.h as i32);

    // Backdrop + card
    fill_rect(fb, 0, 0, w, h, pack32(fb.fmt, 8, 12, 18));
    let card_w = (w * 3) / 5;
    let card_h = (h * 2) / 5;
    let px  = w / 2 - card_w / 2;
    let py  = h / 2 - card_h / 2;

    fill_rounded_rect(fb, px, py, card_w, card_h, 12, pack32(fb.fmt, 18, 26, 38));
    for ii in 0..2 {
        fill_rounded_rect(fb, px + ii, py + ii, card_w - 2*ii, card_h - 2*ii, 10, pack32(fb.fmt, 28, 44, 60));
    }

    // Title
    let title_px: u16 = ((w.min(h) / 18).clamp(20, 56)) as u16;
    let title = "SYSTEM INFO";
    let title_w = measure_width(ctx, title, title_px, false);
    let tx = w / 2 - title_w / 2;
    let ty = py + 28 + title_px as i32;

    let title_shadow = TextStyle { px: title_px, mono: false, color: (40, 190, 230) };
    let title_style  = TextStyle { px: title_px, mono: false, color: (180, 235, 255) };
    let _ = draw_text(ctx, fb, tx + 1, ty + 1, title, title_shadow, LayoutOpts::default());
    let (_tw, th) = draw_text(ctx, fb, tx, ty, title, title_style, LayoutOpts::default());

    // Rows
    let row_px: u16 = ((title_px as i32 * 2 / 3).clamp(14, 40)) as u16;
    let row_style = TextStyle { px: row_px, mono: true, color: (210, 230, 240) };
    let gap = (row_px as i32 + 8).max(22);
    let mut y = ty + (th / 2) + 12;

    let mut b12 = [0u8; 12];
    let mut b12b = [0u8; 12];
    let mut b12c = [0u8; 12];
    let w_str = u32_to_str(&mut b12, fb.w);
    let h_str = u32_to_str(&mut b12b, fb.h);
    let bpp_str = u32_to_str(&mut b12c, fb.bpp as u32);

    let x_left = px + 24;
    let mut x = x_left;
    x += draw(ctx, fb, x, y, "Resolution: ", row_style);
    x += draw(ctx, fb, x, y, w_str, row_style);
    x += draw(ctx, fb, x, y, " × ", row_style);
    x += draw(ctx, fb, x, y, h_str, row_style);
    x += draw(ctx, fb, x, y, "  @  ", row_style);
    x += draw(ctx, fb, x, y, bpp_str, row_style);
    x += draw(ctx, fb, x, y, " bpp", row_style);
    y += gap;

    let mut b12d = [0u8; 12];
    let pitch_str = u32_to_str(&mut b12d, fb.pitch);
    let fmt_str = if fb.fmt == 1 { "RGB" } else { "BGR" };
    let mut x2 = x_left;
    x2 += draw(ctx, fb, x2, y, "Pitch: ", row_style);
    x2 += draw(ctx, fb, x2, y, pitch_str, row_style);
    x2 += draw(ctx, fb, x2, y, " bytes     Format: ", row_style);
    x2 += draw(ctx, fb, x2, y, fmt_str, row_style);
    y += gap;

    if let Some(bytes) = mem_bytes {
        let mut b21 = [0u8; 21];
        let mib = mib_str(&mut b21, bytes);
        let mut x3 = x_left;
        x3 += draw(ctx, fb, x3, y, "Memory: ", row_style);
        x3 += draw(ctx, fb, x3, y, mib, row_style);
        x3 += draw(ctx, fb, x3, y, " MiB", row_style);
        y += gap;
    }

    let hint_px: u16 = (row_px as i32 * 3 / 4).max(12) as u16;
    let hint_shadow = TextStyle { px: hint_px, mono: true, color: (40, 190, 230) };
    let hint_style  = TextStyle { px: hint_px, mono: true, color: (180, 235, 255) };
    let hint = "Press any key to return";
    let _ = draw_text(ctx, fb, x_left + 1, y + 1, hint, hint_shadow, LayoutOpts::default());
    let _ = draw_text(ctx, fb, x_left, y, hint, hint_style, LayoutOpts::default());
}

// Draw text and return its advance (px)
#[inline]
fn draw(ctx: &mut TextCtx, fb: &Fb, x: i32, baseline_y: i32, s: &str, style: TextStyle) -> i32 {
    let (w, _) = draw_text(ctx, fb, x, baseline_y, s, style, LayoutOpts::default());
    w
}
