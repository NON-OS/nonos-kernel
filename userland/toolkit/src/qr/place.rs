use crate::qr::format::QrSpec;
use crate::qr::mask;

fn set(buf: &mut [u8], size: usize, x: usize, y: usize, v: u8) {
	let i = y.saturating_mul(size).saturating_add(x);
	if i < buf.len() {
		buf[i] = v;
	}
}

fn place_finder(buf: &mut [u8], size: usize, ox: usize, oy: usize) {
	let mut y = 0usize;
	while y < 7 {
		let mut x = 0usize;
		while x < 7 {
			let b = x == 0 || y == 0 || x == 6 || y == 6 || (x >= 2 && x <= 4 && y >= 2 && y <= 4);
			set(buf, size, ox + x, oy + y, if b { 1 } else { 0 });
			x += 1;
		}
		y += 1;
	}
}

pub fn place_payload(spec: QrSpec, data: &[u8], matrix: &mut [u8]) -> usize {
	let size = spec.size as usize;
	let count = size.saturating_mul(size);
	if matrix.len() < count {
		return 0;
	}
	matrix[..count].fill(0);
	place_finder(matrix, size, 0, 0);
	place_finder(matrix, size, size - 7, 0);
	place_finder(matrix, size, 0, size - 7);
	let mut bit = 0usize;
	let mut y = 0usize;
	while y < size {
		let mut x = 0usize;
		while x < size {
			let in_finder = (x < 7 && y < 7) || (x >= size - 7 && y < 7) || (x < 7 && y >= size - 7);
			if in_finder {
				x += 1;
				continue;
			}
			let byte = bit / 8;
			let mask_bit = 7 - (bit & 7);
			let mut v = if byte < data.len() { (data[byte] >> mask_bit) & 1 } else { 0 };
			if mask::applies(spec.mask, y as u8, x as u8) {
				v ^= 1;
			}
			set(matrix, size, x, y, v);
			bit += 1;
			x += 1;
		}
		y += 1;
	}
	count
}
