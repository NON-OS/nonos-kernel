use crate::design::color::Argb;
use crate::font::render::draw_text;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LabelStyle {
	pub color: Argb,
}

impl Default for LabelStyle {
	fn default() -> Self {
		Self { color: Argb::WHITE }
	}
}

pub fn render_label(
	buf: &mut [u32],
	stride: usize,
	w: u32,
	h: u32,
	x: u32,
	y: u32,
	text: &[u8],
	style: LabelStyle,
) {
	draw_text(buf, stride, w, h, x, y, text, style.color.as_u32());
}
