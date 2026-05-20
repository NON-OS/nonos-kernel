use crate::animation::easing::Curve;
use crate::animation::state::Animation;
use crate::animation::timing::DurationMs;

pub fn start_fade(anim: &mut Animation, from_alpha: u8, to_alpha: u8, duration_ms: u32) {
    anim.start(from_alpha as i32, to_alpha as i32, DurationMs(duration_ms), Curve::EaseInOut);
}

pub fn start_slide_x(anim: &mut Animation, from_x: i32, to_x: i32, duration_ms: u32) {
    anim.start(from_x, to_x, DurationMs(duration_ms), Curve::EaseOut);
}
