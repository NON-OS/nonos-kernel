pub fn parity_ecc(data: &[u8], out: &mut [u8]) -> usize {
	if out.is_empty() {
		return 0;
	}
	let mut p0 = 0u8;
	let mut p1 = 0u8;
	let mut i = 0usize;
	while i < data.len() {
		let b = data[i];
		p0 ^= b;
		p1 = p1.wrapping_add((i as u8).wrapping_mul(17) ^ b.rotate_left((i & 7) as u32));
		i += 1;
	}
	out[0] = p0;
	if out.len() > 1 {
		out[1] = p1;
		2
	} else {
		1
	}
}
