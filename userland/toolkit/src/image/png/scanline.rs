use crate::image::types::DecodeError;

pub fn unfilter_none_only(raw: &[u8], width: u32, height: u32, out: &mut [u8]) -> Result<usize, DecodeError> {
	let row_bytes = width as usize * 4;
	let needed = (row_bytes + 1).saturating_mul(height as usize);
	if raw.len() < needed {
		return Err(DecodeError::Truncated);
	}
	let out_needed = row_bytes.saturating_mul(height as usize);
	if out.len() < out_needed {
		return Err(DecodeError::OutputTooSmall);
	}
	let mut src = 0usize;
	let mut dst = 0usize;
	let mut row = 0usize;
	while row < height as usize {
		if raw[src] != 0 {
			return Err(DecodeError::Unsupported);
		}
		src += 1;
		out[dst..dst + row_bytes].copy_from_slice(&raw[src..src + row_bytes]);
		src += row_bytes;
		dst += row_bytes;
		row += 1;
	}
	Ok(out_needed)
}
