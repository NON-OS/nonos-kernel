use crate::design::color::Argb;
use crate::font::render::draw_text;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputStyle {
    pub bg: Argb,
    pub fg: Argb,
    pub caret: Argb,
}

impl Default for InputStyle {
    fn default() -> Self {
        Self {
            bg: Argb::from_channels(0xFF, 0x14, 0x18, 0x21),
            fg: Argb::from_channels(0xFF, 0xE6, 0xE9, 0xEE),
            caret: Argb::from_channels(0xFF, 0x67, 0xB7, 0xFF),
        }
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
    let mut py = y.min(h) as usize;
    while py < (y + rh).min(h) as usize {
        let mut px = x.min(w) as usize;
        while px < (x + rw).min(w) as usize {
            let i = py.saturating_mul(stride).saturating_add(px);
            if i < buf.len() {
                buf[i] = color;
            }
            px += 1;
        }
        py += 1;
    }
}

pub fn render_input(
    buf: &mut [u32],
    stride: usize,
    w: u32,
    h: u32,
    x: u32,
    y: u32,
    rw: u32,
    rh: u32,
    text: &[u8],
    caret_col: usize,
    style: InputStyle,
) {
    fill_rect(buf, stride, w, h, x, y, rw, rh, style.bg.as_u32());
    draw_text(buf, stride, w, h, x.saturating_add(4), y.saturating_add(4), text, style.fg.as_u32());
    let cx = x.saturating_add(4 + (caret_col as u32).saturating_mul(9));
    fill_rect(
        buf,
        stride,
        w,
        h,
        cx,
        y.saturating_add(3),
        1,
        rh.saturating_sub(6),
        style.caret.as_u32(),
    );
}
