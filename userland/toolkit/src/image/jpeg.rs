use crate::image::types::{DecodeError, ImageSize};

pub fn decode_jpeg_argb8888(_input: &[u8], _out: &mut [u32]) -> Result<ImageSize, DecodeError> {
	Err(DecodeError::Unsupported)
}
