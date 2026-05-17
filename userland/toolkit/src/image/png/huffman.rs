use crate::image::types::DecodeError;

pub struct HuffmanTable;

impl HuffmanTable {
	pub fn fixed_literal_length() -> Self {
		Self
	}

	pub fn fixed_distance() -> Self {
		Self
	}

	pub fn decode_symbol(&self, _bits: &mut crate::image::png::deflate::BitReader<'_>) -> Result<u16, DecodeError> {
		Err(DecodeError::Unsupported)
	}
}
