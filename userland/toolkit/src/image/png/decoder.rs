use crate::image::png::{inflate::inflate_zlib_stored_only, scanline::unfilter_none_only};
use crate::image::types::{DecodeError, ImageSize};

const PNG_SIG: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

fn be_u32(input: &[u8], off: usize) -> Result<u32, DecodeError> {
	let b = input.get(off..off + 4).ok_or(DecodeError::Truncated)?;
	Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn decode_png_argb8888(input: &[u8], out: &mut [u32]) -> Result<ImageSize, DecodeError> {
	if input.get(0..8) != Some(&PNG_SIG) {
		return Err(DecodeError::BadMagic);
	}
	let ihdr_len = be_u32(input, 8)? as usize;
	if ihdr_len != 13 || input.get(12..16) != Some(b"IHDR") {
		return Err(DecodeError::Unsupported);
	}
	let width = be_u32(input, 16)?;
	let height = be_u32(input, 20)?;
	let size = ImageSize::new(width, height)?;
	if input.get(24) != Some(&8) || input.get(25) != Some(&6) || input.get(26) != Some(&0) {
		return Err(DecodeError::Unsupported);
	}
	let idat_off = 8 + 4 + 4 + 13 + 4;
	let idat_len = be_u32(input, idat_off)? as usize;
	if input.get(idat_off + 4..idat_off + 8) != Some(b"IDAT") {
		return Err(DecodeError::Unsupported);
	}
	let idat = input
		.get(idat_off + 8..idat_off + 8 + idat_len)
		.ok_or(DecodeError::Truncated)?;
	let pixel_count = size.pixel_count() as usize;
	if pixel_count > out.len() {
		return Err(DecodeError::OutputTooSmall);
	}
	let mut deflated = [0u8; 65536];
	let mut rgba = [0u8; 65536];
	let n = inflate_zlib_stored_only(idat, &mut deflated)?;
	let rgba_n = unfilter_none_only(&deflated[..n], width, height, &mut rgba)?;
	if rgba_n != pixel_count * 4 {
		return Err(DecodeError::Truncated);
	}
	let mut i = 0usize;
	while i < pixel_count {
		let o = i * 4;
		let r = rgba[o] as u32;
		let g = rgba[o + 1] as u32;
		let b = rgba[o + 2] as u32;
		let a = rgba[o + 3] as u32;
		out[i] = (a << 24) | (r << 16) | (g << 8) | b;
		i += 1;
	}
	Ok(size)
}
