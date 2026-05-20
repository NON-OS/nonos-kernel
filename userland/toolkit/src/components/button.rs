use crate::design::color::Argb;
use crate::font::render::draw_text;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ButtonStyle {
    pub bg: Argb,
    pub fg: Argb,
}

impl Default for ButtonStyle {
    fn default() -> Self {
        Self { bg: Argb::from_channels(0xFF, 0x2A, 0x7D, 0xD6), fg: Argb::WHITE }
    }
}

fn fill_rect(
    buf: &mut [u32],
    stride: usize,
    w: u32,
    h: u32,
    x: u32,
    y: u32,
    rw: u32,
    rh: u32,
    color: u32,
) {
    let x0 = x.min(w) as usize;
    let y0 = y.min(h) as usize;
    let x1 = (x + rw).min(w) as usize;
    let y1 = (y + rh).min(h) as usize;
    let mut py = y0;
    while py < y1 {
        let mut px = x0;
        while px < x1 {
            let i = py.saturating_mul(stride).saturating_add(px);
            if i < buf.len() {
                buf[i] = color;
            }
            px += 1;
        }
        py += 1;
    }
}

pub fn render_button(
    buf: &mut [u32],
    stride: usize,
    w: u32,
    h: u32,
    x: u32,
    y: u32,
    rw: u32,
    rh: u32,
    label: &[u8],
    style: ButtonStyle,
) {
    fill_rect(buf, stride, w, h, x, y, rw, rh, style.bg.as_u32());
    draw_text(
        buf,
        stride,
        w,
        h,
        x.saturating_add(6),
        y.saturating_add(6),
        label,
        style.fg.as_u32(),
    );
}
