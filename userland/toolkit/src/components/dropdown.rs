use crate::components::list::{render_list_item, ListStyle};
use crate::design::color::Argb;
use crate::font::render::draw_text;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropdownStyle {
    pub bg: Argb,
    pub fg: Argb,
    pub list: ListStyle,
}

impl Default for DropdownStyle {
    fn default() -> Self {
        Self {
            bg: Argb::from_channels(0xFF, 0x1A, 0x22, 0x30),
            fg: Argb::from_channels(0xFF, 0xEA, 0xEE, 0xF3),
            list: ListStyle::default(),
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

pub fn render_dropdown(
    buf: &mut [u32],
    stride: usize,
    w: u32,
    h: u32,
    x: u32,
    y: u32,
    rw: u32,
    row_h: u32,
    selected: &[u8],
    expanded: bool,
    options: &[&[u8]],
    index: usize,
    style: DropdownStyle,
) {
    fill_rect(buf, stride, w, h, x, y, rw, row_h, style.bg.as_u32());
    draw_text(
        buf,
        stride,
        w,
        h,
        x.saturating_add(4),
        y.saturating_add(4),
        selected,
        style.fg.as_u32(),
    );
    if !expanded {
        return;
    }
    let mut i = 0usize;
    while i < options.len() {
        let oy = y.saturating_add(row_h.saturating_mul((i + 1) as u32));
        render_list_item(buf, stride, w, h, x, oy, rw, row_h, options[i], i == index, style.list);
        i += 1;
    }
}
