use crate::design::color::Argb;
use crate::font::render::draw_text;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListStyle {
	pub fg: Argb,
	pub active_bg: Argb,
}

impl Default for ListStyle {
	fn default() -> Self {
		Self {
			fg: Argb::from_channels(0xFF, 0xE7, 0xEB, 0xF0),
			active_bg: Argb::from_channels(0xFF, 0x1A, 0x2D, 0x45),
		}
	}
}

fn fill_rect(buf: &mut [u32], stride: usize, w: u32, h: u32, x: u32, y: u32, rw: u32, rh: u32, color: u32) {
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

pub fn render_list_item(
	buf: &mut [u32], stride: usize, w: u32, h: u32, x: u32, y: u32, rw: u32, rh: u32, text: &[u8], active: bool, style: ListStyle,
) {
	if active {
		fill_rect(buf, stride, w, h, x, y, rw, rh, style.active_bg.as_u32());
	}
	draw_text(buf, stride, w, h, x.saturating_add(4), y.saturating_add(4), text, style.fg.as_u32());
}
