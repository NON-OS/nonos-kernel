use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SliderStyle {
    pub track: Argb,
    pub fill: Argb,
}

impl Default for SliderStyle {
    fn default() -> Self {
        Self {
            track: Argb::from_channels(0xFF, 0x2A, 0x2F, 0x3A),
            fill: Argb::from_channels(0xFF, 0x3C, 0xA9, 0x6B),
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

pub fn render_slider(
    buf: &mut [u32],
    stride: usize,
    w: u32,
    h: u32,
    x: u32,
    y: u32,
    rw: u32,
    rh: u32,
    value_pct: u8,
    style: SliderStyle,
) {
    fill_rect(buf, stride, w, h, x, y, rw, rh, style.track.as_u32());
    let fill_w = rw.saturating_mul(value_pct.min(100) as u32) / 100;
    fill_rect(buf, stride, w, h, x, y, fill_w, rh, style.fill.as_u32());
}
