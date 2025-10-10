#![allow(clippy::identity_op)]

use core::ptr;
use crate::gfx::{Fb, FMT_RGB};

#[inline]
fn pack32(fmt: u16, r: u8, g: u8, b: u8) -> u32 {
    match fmt {
        FMT_RGB => ((r as u32) << 16) | ((g as u32) << 8) | (b as u32),
        _       => ((b as u32) << 16) | ((g as u32) << 8) | (r as u32),
    }
}

#[inline]
unsafe fn put_px(fb: &Fb, x: i32, y: i32, c: u32) {
    if x < 0 || y < 0 { return; }
    let (x,y) = (x as u32, y as u32);
    if x >= fb.w || y >= fb.h { return; }
    let bpp = (fb.bpp as usize) / 8;
    let off = (y as usize) * (fb.pitch as usize) + (x as usize) * bpp;
    ptr::write_unaligned(fb.base.add(off) as *mut u32, c);
}

fn lerp_u8(a: u8, b: u8, t_num: i32, t_den: i32) -> u8 {
    let a = a as i32;
    let b = b as i32;
    (a + (b - a) * t_num / t_den).clamp(0, 255) as u8
}

fn blend_add_sat(fmt: u16, dst: (u8,u8,u8), src: (u8,u8,u8)) -> u32 {
    let r = dst.0.saturating_add(src.0);
    let g = dst.1.saturating_add(src.1);
    let b = dst.2.saturating_add(src.2);
    pack32(fmt, r,g,b)
}

fn sample_rgb(fb: &Fb, x: i32, y: i32) -> (u8,u8,u8) {
    if x < 0 || y < 0 { return (0,0,0); }
    let (x,y) = (x as u32, y as u32);
    if x >= fb.w || y >= fb.h { return (0,0,0); }
    let off = (y as usize) * (fb.pitch as usize) + (x as usize) * ((fb.bpp as usize) / 8);
    let v = unsafe { ptr::read_unaligned(fb.base.add(off) as *const u32) };
    match fb.fmt {
        FMT_RGB => (((v>>16)&0xFF) as u8, ((v>>8)&0xFF) as u8, (v&0xFF) as u8),
        _       => (((v>>0)&0xFF)  as u8, ((v>>8)&0xFF) as u8, ((v>>16)&0xFF) as u8),
    }
}

fn fill_rect(fb: &Fb, x0: i32, y0: i32, w: i32, h: i32, c: u32) {
    for y in y0..y0+h {
        for x in x0..x0+w {
            unsafe { put_px(fb, x, y, c); }
        }
    }
}

fn fill_rounded_rect(fb: &Fb, x0: i32, y0: i32, w: i32, h: i32, r: i32, c: u32) {
    if h > 2*r { fill_rect(fb, x0, y0+r, w, h-2*r, c); }
    for dy in 0..r {
        let y_top = y0 + dy;
        let y_bot = y0 + h - 1 - dy;
        let dx = circle_hspan(r, dy);
        let left = x0 + r - dx;
        let right = x0 + w - r + dx - 1;
        for x in left..=right {
            unsafe { put_px(fb, x, y_top, c); }
            unsafe { put_px(fb, x, y_bot, c); }
        }
    }
}

fn circle_hspan(r: i32, y: i32) -> i32 {
    let y2 = (y*y) as i64;
    let r2 = (r*r) as i64;
    let mut x = r as i64;
    while x*x + y2 > r2 { x -= 1; }
    x as i32
}

fn draw_ring(fb: &Fb, cx: i32, cy: i32, r: i32, thickness: i32, color: u32, arc_numer: i32, arc_denom: i32) {
    let r2_outer = r * r;
    let r2_inner = (r - thickness).max(0);
    let r2_inner = r2_inner * r2_inner;

    let sweep = arc_numer * 360 / arc_denom;
    for y in -r..=r {
        let yy = y*y;
        for x in -r..=r {
            let d2 = x*x + yy;
            if d2 <= r2_outer && d2 >= r2_inner {
                if angle_ok(x, y, sweep) {
                    unsafe { put_px(fb, cx + x, cy + y, color); }
                }
            }
        }
    }
}

fn angle_ok(x: i32, y: i32, sweep_deg: i32) -> bool {
    if sweep_deg >= 360 { return true; }
    let quad = if y >= 0 { if x >= 0 { 0 } else { 1 } } else { if x < 0 { 2 } else { 3 } };
    let limit_quad = sweep_deg / 90;
    if quad < limit_quad { return true; }
    if quad > limit_quad { return false; }
    match quad {
        0 => x * 90 >=  (sweep_deg % 90) * (x.abs().max(1)),
        1 => y * 90 >=  (sweep_deg % 90) * (y.abs().max(1)),
        2 => (-x) * 90 >= (sweep_deg % 90) * (x.abs().max(1)),
        _ => (-y) * 90 >= (sweep_deg % 90) * (y.abs().max(1)),
    }
}

// --- Tiny 8x16 font (subset) ---
fn glyph8x16(ch: u8) -> [u8;16] {
    match ch {
        b' ' => [0;16],
        b'A' => [0x18,0x3C,0x66,0x66,0x66,0x7E,0x7E,0x66,0x66,0x66,0x66,0x00,0,0,0,0],
        b'C' => [0x3C,0x7E,0xE7,0xC3,0xC0,0xC0,0xC0,0xC3,0xE7,0x7E,0x3C,0x00,0,0,0,0],
        b'E' => [0x7E,0x7E,0x60,0x60,0x7C,0x7C,0x60,0x60,0x60,0x7E,0x7E,0x00,0,0,0,0],
        b'G' => [0x3C,0x7E,0xE7,0xC3,0xC0,0xCF,0xCF,0xC3,0xE7,0x7E,0x3C,0x00,0,0,0,0],
        b'I' => [0x7E,0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x7E,0x00,0,0,0,0],
        b'K' => [0x66,0x6C,0x78,0x70,0x60,0x60,0x70,0x78,0x6C,0x66,0x63,0x00,0,0,0,0],
        b'L' => [0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x7E,0x7E,0x00,0,0,0,0],
        b'M' => [0x63,0x77,0x7F,0x7F,0x6B,0x63,0x63,0x63,0x63,0x63,0x63,0x00,0,0,0,0],
        b'N' => [0x63,0x73,0x7B,0x7F,0x6F,0x67,0x63,0x63,0x63,0x63,0x63,0x00,0,0,0,0],
        b'O' => [0x3C,0x7E,0xE7,0xC3,0xC3,0xC3,0xC3,0xC3,0xE7,0x7E,0x3C,0x00,0,0,0,0],
        b'P' => [0x7C,0x7E,0x63,0x63,0x7E,0x7C,0x60,0x60,0x60,0x60,0x60,0x00,0,0,0,0],
        b'R' => [0x7C,0x7E,0x63,0x63,0x7E,0x7C,0x6C,0x66,0x63,0x63,0x63,0x00,0,0,0,0],
        b'S' => [0x3E,0x7F,0x61,0x60,0x7C,0x3E,0x07,0x03,0x63,0x7F,0x3E,0x00,0,0,0,0],
        b'T' => [0x7E,0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0,0,0,0],
        b'U' => [0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x7F,0x3E,0x00,0,0,0,0],
        b'V' => [0x63,0x63,0x63,0x63,0x63,0x63,0x36,0x36,0x1C,0x1C,0x08,0x00,0,0,0,0],
        b'W' => [0x63,0x63,0x63,0x6B,0x6B,0x6B,0x7F,0x7F,0x77,0x63,0x63,0x00,0,0,0,0],
        b'Y' => [0x63,0x63,0x36,0x36,0x1C,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0,0,0,0],
        b'Z' => [0x7F,0x7F,0x06,0x0C,0x18,0x30,0x30,0x60,0x60,0x7F,0x7F,0x00,0,0,0,0],
        b'0' => [0x3C,0x7E,0xE7,0xC3,0xCB,0xDB,0xD3,0xC3,0xE7,0x7E,0x3C,0x00,0,0,0,0],
        b'1' => [0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x7E,0x00,0,0,0,0],
        b'-' => [0x00,0x00,0x00,0x00,0x00,0x3C,0x3C,0x00,0x00,0x00,0x00,0x00,0,0,0,0],
        b' ' => [0;16],
        _    => [0;16],
    }
}

fn draw_glyph_scaled(fb: &Fb, ch: u8, x0: i32, y0: i32, scale: i32, color: u32) {
    let g = glyph8x16(ch);

    // keep loop counters as i32 for math; cast only when indexing
    for row in 0..16_i32 {
        let bits: u8 = g[row as usize];
        for col in 0..8_i32 {
            let mask: u8 = 1u8 << ((7 - col) as u8);
            if (bits & mask) != 0 {
                for dy in 0..scale {
                    for dx in 0..scale {
                        // all i32 now, matches put_px signature
                        unsafe {
                            put_px(
                                fb,
                                x0 + col * scale + dx,
                                y0 + row * scale + dy,
                                color,
                            );
                        }
                    }
                }
            }
        }
    }
}


fn draw_text_scaled(fb: &Fb, s: &[u8], mut x: i32, y: i32, scale: i32, color: u32) {
    for &ch in s {
        draw_glyph_scaled(fb, ch, x, y, scale, color);
        x += 8 * scale;
    }
}

// -------------------- MAIN RENDER --------------------

pub unsafe fn render_dashboard(fb: &Fb) {
    let (w, h) = (fb.w as i32, fb.h as i32);

    // background gradient + grid
    for y in 0..h {
        let r = lerp_u8(8,  14, y, h.max(1));
        let g = lerp_u8(14, 40, y, h.max(1));
        let b = lerp_u8(22, 64, y, h.max(1));
        let mut c = pack32(fb.fmt, r,g,b);
        if y % 32 == 0 {
            c = pack32(fb.fmt, r.saturating_add(4), g.saturating_add(8), b.saturating_add(10));
        }
        for x in 0..w { put_px(fb, x, y, c); }
    }
    for x in (0..w).step_by(56usize) {
        for y in 0..h {
            let (r,g,b) = sample_rgb(fb, x, y);
            let c = pack32(fb.fmt, r.saturating_add(6), g.saturating_add(8), b.saturating_add(8));
            put_px(fb, x, y, c);
        }
    }

    // Title
    let title = b"NONOS";
    let title_scale = (w.min(h) / 80).clamp(4, 18);
    let title_w = (title.len() as i32) * 8 * title_scale;
    let title_x = w/2 - title_w/2;
    let title_y = h/3 - (16*title_scale)/2;

    let glow1 = pack32(fb.fmt,  20, 220, 255);
    let white = pack32(fb.fmt, 230, 245, 255);

    draw_text_scaled(fb, title, title_x-2, title_y,   title_scale, glow1);
    draw_text_scaled(fb, title, title_x+2, title_y,   title_scale, glow1);
    draw_text_scaled(fb, title, title_x,   title_y-2, title_scale, glow1);
    draw_text_scaled(fb, title, title_x,   title_y+2, title_scale, glow1);
    draw_text_scaled(fb, title, title_x,   title_y,   title_scale, white);

    // Subtitle
    let sub = b"ZEROSTATE  SOVEREIGN COMPUTE";
    let sub_scale = (title_scale/2).max(3);
    let sub_w = (sub.len() as i32) * 8 * sub_scale;
    let sub_x = w/2 - sub_w/2;
    let sub_y = title_y + 16*title_scale + (6*sub_scale);

    draw_text_scaled(fb, sub, sub_x+1, sub_y, sub_scale, pack32(fb.fmt,  40, 190, 230));
    draw_text_scaled(fb, sub, sub_x,   sub_y, sub_scale, pack32(fb.fmt, 180, 235, 255));

    // Status card
    let card_w = (w * 7)/12;
    let card_h = (h * 1)/5;
    let card_x = w/2 - card_w/2;
    let card_y = sub_y + 16*sub_scale + (h/40);

    let base = pack32(fb.fmt, 16, 24, 36);
    fill_rounded_rect(fb, card_x, card_y, card_w, card_h, 12, base);
    let stroke = pack32(fb.fmt, 28, 44, 60);
    for i in 0..2 { fill_rounded_rect(fb, card_x+i, card_y+i, card_w-2*i, card_h-2*i, 10, stroke); }

    for y in card_y+2..card_y+card_h-2 {
        for x in card_x+2..card_x+card_w-2 {
            let src = sample_rgb(fb, x, y);
            let c = blend_add_sat(fb.fmt, src, (0, 6, 12));
            put_px(fb, x, y, c);
        }
    }

    // Left rows
    let row_h = (card_h - 24) / 4;
    let text_scale = (sub_scale*3/4).max(2);
    let left_pad = 24;
    let mut y_row = card_y + 12;

    let rows: [&[u8];4] = [
        b"KERNEL ACTIVE",
        b"MEMORY ACTIVE",
        b"NETWORK ONION MESH",
        b"SECURITY VERIFIED",
    ];

    for (i, label) in rows.iter().enumerate() {
        let color_line = match i {
            0 => pack32(fb.fmt,  20, 220, 255),
            1 => pack32(fb.fmt,  20, 255, 180),
            2 => pack32(fb.fmt, 180, 120, 255),
            _ => pack32(fb.fmt,  80, 255, 200),
        };
        fill_rect(fb, card_x + left_pad - 8, y_row + row_h/2 - 4, 6, 6, color_line);
        draw_text_scaled(fb, label, card_x + left_pad + 4, y_row + row_h/2 - 8*text_scale/2, text_scale, pack32(fb.fmt, 210, 235, 250));
        if i != rows.len()-1 {
            for x in card_x + 16 .. card_x + card_w - 16 {
                put_px(fb, x, y_row + row_h, pack32(fb.fmt, 30, 46, 64));
            }
        }
        y_row += row_h;
    }

    // Right ring
    let ring_cx = card_x + card_w - (card_h/2);
    let ring_cy = card_y + card_h/2;
    let ring_r  = (row_h * 3 / 4).max(24);
    let ring_th = (ring_r / 4).max(6);

    draw_ring(fb, ring_cx, ring_cy, ring_r, ring_th, pack32(fb.fmt, 24, 60, 80), 360, 360);
    draw_ring(fb, ring_cx, ring_cy, ring_r, ring_th, pack32(fb.fmt,  20, 220, 255), 270, 360);

    // Footer
    let foot = b"PRESS <- TO CONTINUE";
    let foot_scale = (text_scale*3/4).max(2);
    let foot_w = (foot.len() as i32) * 8 * foot_scale;
    let fx = w/2 - foot_w/2;
    let fy = card_y + card_h + (h/16);

    draw_text_scaled(fb, foot, fx+1, fy, foot_scale, pack32(fb.fmt,  40, 190, 230));
    draw_text_scaled(fb, foot, fx,   fy, foot_scale, pack32(fb.fmt, 180, 235, 255));
}
