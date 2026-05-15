pub fn applies(mask_id: u8, row: u8, col: u8) -> bool {
	let r = row as u16;
	let c = col as u16;
	match mask_id & 0x07 {
		0 => ((r + c) & 1) == 0,
		1 => (r & 1) == 0,
		2 => c % 3 == 0,
		3 => (r + c) % 3 == 0,
		4 => (((r / 2) + (c / 3)) & 1) == 0,
		5 => ((r * c) % 2 + (r * c) % 3) == 0,
		6 => ((((r * c) % 2) + ((r * c) % 3)) & 1) == 0,
		_ => ((((r + c) % 2) + ((r * c) % 3)) & 1) == 0,
	}
}
