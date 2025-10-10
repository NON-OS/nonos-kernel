#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

pub const FMT_RGB: u16 = 1;
pub const FMT_BGR: u16 = 2;

#[derive(Clone, Copy)]
pub struct Fb {
    pub base: *mut u8,
    pub size: usize,
    pub pitch: u32, // bytes per scanline
    pub w: u32,
    pub h: u32,
    pub bpp: u16, // expect 32
    pub fmt: u16, // 1=RGB, 2=BGR
}
impl Fb {
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.base as usize != 0 && self.w > 0 && self.h > 0 && self.bpp == 32
    }
}

#[inline(always)]
pub fn pack32(fmt: u16, r: u8, g: u8, b: u8) -> u32 {
    match fmt {
        FMT_RGB => ((r as u32) << 16) | ((g as u32) << 8) | (b as u32),
        _ => ((b as u32) << 16) | ((g as u32) << 8) | (r as u32), // BGR
    }
}

// NEW: inverse of pack32 → get (r,g,b) consistently
#[inline(always)]
pub fn unpack32(fmt: u16, px: u32) -> (u8, u8, u8) {
    match fmt {
        FMT_RGB => (
            ((px >> 16) & 0xFF) as u8,
            ((px >> 8) & 0xFF) as u8,
            (px & 0xFF) as u8,
        ),
        _ => (
            (px & 0xFF) as u8,
            ((px >> 8) & 0xFF) as u8,
            ((px >> 16) & 0xFF) as u8,
        ),
    }
}

#[inline(always)]
unsafe fn row_ptr(fb: &Fb, y: u32) -> *mut u32 {
    fb.base.add((y as usize) * (fb.pitch as usize)) as *mut u32
}

#[inline(always)]
pub unsafe fn put_px(fb: &Fb, x: u32, y: u32, c: u32) {
    if x >= fb.w || y >= fb.h {
        return;
    }
    let p = row_ptr(fb, y).add(x as usize);
    core::ptr::write_volatile(p, c);
}

// NEW: read pixel helper (volatile)
#[inline(always)]
pub unsafe fn get_px(fb: &Fb, x: u32, y: u32) -> u32 {
    if x >= fb.w || y >= fb.h {
        return 0;
    }
    let p = row_ptr(fb, y).add(x as usize);
    core::ptr::read_volatile(p)
}

#[inline(always)]
pub unsafe fn fill_rect(fb: &Fb, x: i32, y: i32, w: i32, h: i32, c: u32) {
    if w <= 0 || h <= 0 {
        return;
    }
    let mut yy = y.max(0) as u32;
    let y_end = (y + h).min(fb.h as i32) as u32;
    let x0 = x.max(0) as u32;
    let x1 = (x + w).min(fb.w as i32) as u32;
    while yy < y_end {
        let row = row_ptr(fb, yy);
        let mut xx = x0;
        while xx < x1 {
            core::ptr::write_volatile(row.add(xx as usize), c);
            xx += 1;
        }
        yy += 1;
    }
}

pub unsafe fn vertical_gradient(fb: &Fb, top: (u8, u8, u8), bot: (u8, u8, u8)) {
    let (tr, tg, tb) = top;
    let (br, bg, bb) = bot;
    let h = fb.h as i32;
    for y in 0..(fb.h as i32) {
        let t = (y as i64) * 65535 / (h.max(1) as i64);
        let inv = 65535 - t;
        let r = (((tr as i64) * inv + (br as i64) * t) / 65535) as u8;
        let g = (((tg as i64) * inv + (bg as i64) * t) / 65535) as u8;
        let b = (((tb as i64) * inv + (bb as i64) * t) / 65535) as u8;
        let c = pack32(fb.fmt, r, g, b);
        let row = row_ptr(fb, y as u32);
        for x in 0..fb.w {
            core::ptr::write_volatile(row.add(x as usize), c);
        }
    }
}

#[inline(always)]
fn lerp_u8(a: u8, b: u8, t256: u32) -> u8 {
    let a = a as u32;
    let b = b as u32;
    (((a * (256 - t256)) + (b * t256)) >> 8) as u8
}

// darken towards the edges (simple vignette)
pub unsafe fn vignette_edges(fb: &Fb, max_alpha: u8) {
    let center_x = (fb.w / 2) as i32;
    let center_y = (fb.h / 2) as i32;
    let maxd = ((center_x * center_x + center_y * center_y) as i64).max(1);
    for y in 0..fb.h {
        let row = row_ptr(fb, y);
        for x in 0..fb.w {
            let dx = x as i32 - center_x;
            let dy = y as i32 - center_y;
            let d2 = (dx * dx + dy * dy) as i64;
            let t = (d2 * 255 / maxd) as u32; // 0..255
            let a = (t.min(255) as u8).saturating_mul(max_alpha) / 255;
            if a == 0 {
                continue;
            }

            let p = row.add(x as usize);
            let px = core::ptr::read_volatile(p);
            let (mut r, mut g, mut b) = unpack32(fb.fmt, px);
            let t256 = a as u32; // 0..255
            r = lerp_u8(r, 0, t256);
            g = lerp_u8(g, 0, t256);
            b = lerp_u8(b, 0, t256);
            let out = pack32(fb.fmt, r, g, b);
            core::ptr::write_volatile(p, out);
        }
    }
}

// Top progress bands with subtle separators
pub unsafe fn top_progress_bands(fb: &Fb, pct_x256: u32) {
    let bar_h = (fb.h / 60).max(6); // proportional
    let pad = (fb.h / 200).max(2) as i32;
    let y0 = pad;
    let y1 = y0 + bar_h as i32;
    let y2 = y1 + 2 + bar_h as i32;

    // Tracks
    let track = pack32(fb.fmt, 240, 240, 240);
    fill_rect(fb, 0, y0, fb.w as i32, bar_h as i32, track);
    fill_rect(fb, 0, y2, fb.w as i32, bar_h as i32, track);

    // Fills
    let full = (pct_x256 * fb.w as u32 / 256) as i32;
    let fill1 = pack32(fb.fmt, 0x2D, 0x7D, 0xF7); // blue
    let fill2 = pack32(fb.fmt, 0xF7, 0xA4, 0x2D); // orange
    fill_rect(fb, 0, y0, full, bar_h as i32, fill1);
    fill_rect(fb, 0, y2, full * 3 / 4, bar_h as i32, fill2);

    // separators
    let sep = pack32(fb.fmt, 200, 200, 200);
    fill_rect(fb, 0, y1, fb.w as i32, 1, sep);
    fill_rect(fb, 0, y2 - 2, fb.w as i32, 1, sep);
}

/* ============================
   NEW: Alpha blending helpers
   ============================ */

#[inline(always)]
fn blend_chan(dst: u8, src: u8, a: u8) -> u8 {
    // linear alpha: out = src*a + dst*(1-a)
    let ia = 255u16 - a as u16;
    (((src as u16 * a as u16) + (dst as u16 * ia)) / 255) as u8
}

/// Blend a solid RGB color over the pixel at (x,y) with alpha `a` (0..=255).
pub unsafe fn blend_px(fb: &Fb, x: u32, y: u32, r: u8, g: u8, b: u8, a: u8) {
    if a == 0 || x >= fb.w || y >= fb.h {
        return;
    }
    // Fast path: full coverage → just store
    if a == 255 {
        put_px(fb, x, y, pack32(fb.fmt, r, g, b));
        return;
    }
    let p = row_ptr(fb, y).add(x as usize);
    let dst_px = core::ptr::read_volatile(p);
    let (dr, dg, db) = unpack32(fb.fmt, dst_px);
    let nr = blend_chan(dr, r, a);
    let ng = blend_chan(dg, g, a);
    let nb = blend_chan(db, b, a);
    core::ptr::write_volatile(p, pack32(fb.fmt, nr, ng, nb));
}

/// Blit an 8-bit alpha mask (e.g., font glyph coverage) tinted with a solid RGB color.
/// `mask` is row-major; `stride` is bytes per source row (often == w).
pub unsafe fn blit_mask_solid(
    fb: &Fb,
    x: i32,
    y: i32,
    w: usize,
    h: usize,
    mask: &[u8],
    stride: usize,
    color: (u8, u8, u8),
) {
    if w == 0 || h == 0 {
        return;
    }
    let (sr, sg, sb) = color;

    for row in 0..(h as i32) {
        let dy = y + row;
        if dy < 0 || dy as u32 >= fb.h {
            continue;
        }
        let src_row = (row as usize) * stride;

        // dest row pointer once per row
        let drow = row_ptr(fb, dy as u32);

        for col in 0..(w as i32) {
            let dx = x + col;
            if dx < 0 || dx as u32 >= fb.w {
                continue;
            }
            let a = mask[src_row + col as usize];
            if a == 0 {
                continue;
            }

            let p = drow.add(dx as usize);
            if a == 255 {
                core::ptr::write_volatile(p, pack32(fb.fmt, sr, sg, sb));
            } else {
                let dst_px = core::ptr::read_volatile(p);
                let (dr, dg, db) = unpack32(fb.fmt, dst_px);
                let nr = blend_chan(dr, sr, a);
                let ng = blend_chan(dg, sg, a);
                let nb = blend_chan(db, sb, a);
                core::ptr::write_volatile(p, pack32(fb.fmt, nr, ng, nb));
            }
        }
    }
}
