// src/text/render.rs
#![allow(dead_code)]
extern crate alloc;

use crate::gfx::{blit_mask_solid, Fb};
use super::TextCtx;

#[derive(Clone, Copy)]
pub struct TextStyle {
    /// Pixel height to rasterize at (approx. "font size")
    pub px: u16,
    /// true = JetBrainsMono, false = Inter
    pub mono: bool,
    /// Solid color tint (r,g,b)
    pub color: (u8, u8, u8),
}

impl Default for TextStyle {
    fn default() -> Self {
        Self { px: 18, mono: false, color: (240, 240, 240) }
    }
}

#[derive(Clone, Copy)]
pub struct LayoutOpts {
    /// Optional wrap width (in pixels) relative to `x` (start column)
    pub max_width: Option<u32>,
    /// Extra pixels between lines (added to `px`)
    pub line_gap: i32,
}

impl Default for LayoutOpts {
    fn default() -> Self {
        Self { max_width: None, line_gap: 2 }
    }
}

/// Draw UTF-8 text at (`x`,`y`) where `y` is the **baseline** of the first line.
/// Returns (width, height) of the drawn block in pixels.
pub fn draw_text(
    ctx: &mut TextCtx,
    fb: &Fb,
    x: i32,
    y: i32,
    text: &str,
    style: TextStyle,
    layout: LayoutOpts,
) -> (i32, i32) {
    let mut cursor_x = x;
    let mut baseline_y = y;
    let mut max_x = x;

    // A tiny helper for wrapping
    let mut newline = |cursor_x: &mut i32, baseline_y: &mut i32| {
        *cursor_x = x;
        *baseline_y += style.px as i32 + layout.line_gap;
    };

    for ch in text.chars() {
        if ch == '\n' {
            newline(&mut cursor_x, &mut baseline_y);
            continue;
        }

        let g = ctx.raster_glyph(ch, style.px, style.mono);

        // Simple word-wrap: if next glyph would exceed max_width, break line first.
        if let Some(maxw) = layout.max_width {
            let next_x = cursor_x + g.advance as i32;
            if (next_x - x) as u32 > maxw && cursor_x != x {
                newline(&mut cursor_x, &mut baseline_y);
            }
        }

        // Place glyph bitmap. We use a pragmatic baseline placement:
        // top-left ≈ (cursor_x + 0, baseline_y - g.h + style.px)
        // This is visually stable for UI text; we can refine with font metrics later.
        let gx = cursor_x;
        let gy = baseline_y - g.h as i32 + style.px as i32;

        unsafe {
            blit_mask_solid(
                fb,
                gx,
                gy,
                g.w,
                g.h,
                &g.alpha,
                g.w,  // stride == width for fontdue bitmaps
                style.color,
            );
        }

        cursor_x += g.advance as i32;
        if cursor_x > max_x {
            max_x = cursor_x;
        }
    }

    let width = (max_x - x).max(0);
    let height = (baseline_y - y + style.px as i32).max(style.px as i32);
    (width, height)
}
