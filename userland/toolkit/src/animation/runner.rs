use crate::animation::state::Animation;

pub fn step_all(anims: &mut [Animation], dt_ms: u32) -> usize {
	let mut active = 0usize;
	let mut i = 0usize;
	while i < anims.len() {
		anims[i].step(dt_ms);
		if anims[i].active {
			active += 1;
		}
		i += 1;
	}
	active
}
