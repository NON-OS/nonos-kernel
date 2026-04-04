use crate::graphics::animation::*;

#[test]
fn test_easing_values() {
    assert_eq!(Easing::Linear, Easing::Linear);
    assert_eq!(Easing::EaseIn, Easing::EaseIn);
    assert_eq!(Easing::EaseOut, Easing::EaseOut);
    assert_eq!(Easing::EaseInOut, Easing::EaseInOut);
    assert_eq!(Easing::Spring, Easing::Spring);
}

#[test]
fn test_easing_inequality() {
    assert_ne!(Easing::Linear, Easing::EaseIn);
    assert_ne!(Easing::EaseIn, Easing::EaseOut);
    assert_ne!(Easing::EaseOut, Easing::EaseInOut);
}

#[test]
fn test_apply_easing_linear() {
    assert_eq!(apply_easing(0.0, Easing::Linear), 0.0);
    assert_eq!(apply_easing(0.5, Easing::Linear), 0.5);
    assert_eq!(apply_easing(1.0, Easing::Linear), 1.0);
}

#[test]
fn test_apply_easing_clamps_input() {
    assert_eq!(apply_easing(-1.0, Easing::Linear), 0.0);
    assert_eq!(apply_easing(2.0, Easing::Linear), 1.0);
}

#[test]
fn test_apply_easing_ease_in() {
    let start = apply_easing(0.0, Easing::EaseIn);
    let middle = apply_easing(0.5, Easing::EaseIn);
    let end = apply_easing(1.0, Easing::EaseIn);

    assert_eq!(start, 0.0);
    assert!(middle < 0.5);
    assert_eq!(end, 1.0);
}

#[test]
fn test_apply_easing_ease_out() {
    let start = apply_easing(0.0, Easing::EaseOut);
    let middle = apply_easing(0.5, Easing::EaseOut);
    let end = apply_easing(1.0, Easing::EaseOut);

    assert_eq!(start, 0.0);
    assert!(middle > 0.5);
    assert_eq!(end, 1.0);
}

#[test]
fn test_apply_easing_ease_in_out() {
    let start = apply_easing(0.0, Easing::EaseInOut);
    let middle = apply_easing(0.5, Easing::EaseInOut);
    let end = apply_easing(1.0, Easing::EaseInOut);

    assert_eq!(start, 0.0);
    assert!((middle - 0.5).abs() < 0.01);
    assert_eq!(end, 1.0);
}

#[test]
fn test_apply_easing_spring() {
    let start = apply_easing(0.0, Easing::Spring);
    let end = apply_easing(1.0, Easing::Spring);

    assert_eq!(start, 0.0);
    assert_eq!(end, 1.0);
}

#[test]
fn test_interpolate() {
    assert_eq!(interpolate(0.0, 100.0, 0.0), 0.0);
    assert_eq!(interpolate(0.0, 100.0, 0.5), 50.0);
    assert_eq!(interpolate(0.0, 100.0, 1.0), 100.0);
}

#[test]
fn test_interpolate_negative() {
    assert_eq!(interpolate(-50.0, 50.0, 0.5), 0.0);
    assert_eq!(interpolate(100.0, 0.0, 0.5), 50.0);
}

#[test]
fn test_interpolate_u32() {
    assert_eq!(interpolate_u32(0, 100, 0.0), 0);
    assert_eq!(interpolate_u32(0, 100, 0.5), 50);
    assert_eq!(interpolate_u32(0, 100, 1.0), 100);
}

#[test]
fn test_interpolate_u32_boundary() {
    assert_eq!(interpolate_u32(0, 100, -1.0), 0);
    assert_eq!(interpolate_u32(0, 100, 2.0), 100);
}

#[test]
fn test_interpolate_color() {
    let black = 0xFF000000u32;
    let white = 0xFFFFFFFFu32;

    let start = interpolate_color(black, white, 0.0);
    let end = interpolate_color(black, white, 1.0);

    assert_eq!(start, black);
    assert_eq!(end, white);
}

#[test]
fn test_interpolate_color_midpoint() {
    let black = 0xFF000000u32;
    let white = 0xFFFFFFFFu32;

    let mid = interpolate_color(black, white, 0.5);
    let r = (mid >> 16) & 0xFF;
    let g = (mid >> 8) & 0xFF;
    let b = mid & 0xFF;

    assert!((r as i32 - 127).abs() <= 1);
    assert!((g as i32 - 127).abs() <= 1);
    assert!((b as i32 - 127).abs() <= 1);
}

#[test]
fn test_interpolate_color_alpha() {
    let transparent = 0x00FF0000u32;
    let opaque = 0xFFFF0000u32;

    let mid = interpolate_color(transparent, opaque, 0.5);
    let a = (mid >> 24) & 0xFF;

    assert!((a as i32 - 127).abs() <= 1);
}

#[test]
fn test_animation_status_values() {
    assert_eq!(AnimationStatus::Idle, AnimationStatus::Idle);
    assert_eq!(AnimationStatus::Running, AnimationStatus::Running);
    assert_eq!(AnimationStatus::Completed, AnimationStatus::Completed);
    assert_eq!(AnimationStatus::Paused, AnimationStatus::Paused);
}

#[test]
fn test_animation_status_inequality() {
    assert_ne!(AnimationStatus::Idle, AnimationStatus::Running);
    assert_ne!(AnimationStatus::Running, AnimationStatus::Completed);
    assert_ne!(AnimationStatus::Completed, AnimationStatus::Paused);
}

#[test]
fn test_animation_new() {
    let anim = Animation::new(0.0, 100.0, 500, Easing::EaseOut);
    assert_eq!(anim.start_value, 0.0);
    assert_eq!(anim.end_value, 100.0);
    assert_eq!(anim.duration_ms, 500);
    assert_eq!(anim.easing, Easing::EaseOut);
    assert_eq!(anim.status, AnimationStatus::Idle);
    assert_eq!(anim.delay_ms, 0);
}

#[test]
fn test_animation_with_delay() {
    let anim = Animation::new(0.0, 1.0, 300, Easing::Linear).with_delay(100);
    assert_eq!(anim.delay_ms, 100);
}

#[test]
fn test_animation_start() {
    let mut anim = Animation::new(0.0, 1.0, 300, Easing::Linear);
    anim.start(1000);
    assert_eq!(anim.status, AnimationStatus::Running);
    assert_eq!(anim.started_at, 1000);
}

#[test]
fn test_animation_progress_idle() {
    let anim = Animation::new(0.0, 1.0, 300, Easing::Linear);
    assert_eq!(anim.progress(1000), 0.0);
}

#[test]
fn test_animation_progress_completed() {
    let mut anim = Animation::new(0.0, 1.0, 300, Easing::Linear);
    anim.complete();
    assert_eq!(anim.progress(1000), 1.0);
}

#[test]
fn test_animation_progress_running() {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(0);
    assert_eq!(anim.progress(0), 0.0);
    assert_eq!(anim.progress(50), 0.5);
    assert_eq!(anim.progress(100), 1.0);
    assert_eq!(anim.progress(200), 1.0);
}

#[test]
fn test_animation_progress_with_delay() {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear).with_delay(50);
    anim.start(0);
    assert_eq!(anim.progress(0), 0.0);
    assert_eq!(anim.progress(50), 0.0);
    assert_eq!(anim.progress(100), 0.5);
    assert_eq!(anim.progress(150), 1.0);
}

#[test]
fn test_animation_current_value() {
    let mut anim = Animation::new(0.0, 100.0, 100, Easing::Linear);
    anim.start(0);
    assert_eq!(anim.current_value(0), 0.0);
    assert_eq!(anim.current_value(50), 50.0);
    assert_eq!(anim.current_value(100), 100.0);
}

#[test]
fn test_animation_is_complete() {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(0);
    assert!(!anim.is_complete(50));
    assert!(anim.is_complete(100));
    assert!(anim.is_complete(200));
}

#[test]
fn test_animation_complete() {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(0);
    anim.complete();
    assert_eq!(anim.status, AnimationStatus::Completed);
}

#[test]
fn test_animation_reset() {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(1000);
    anim.reset();
    assert_eq!(anim.status, AnimationStatus::Idle);
    assert_eq!(anim.started_at, 0);
}

#[test]
fn test_animation_default() {
    let anim = Animation::default();
    assert_eq!(anim.start_value, 0.0);
    assert_eq!(anim.end_value, 1.0);
    assert_eq!(anim.duration_ms, 300);
    assert_eq!(anim.easing, Easing::EaseOut);
}

#[test]
fn test_animation_copy() {
    let anim1 = Animation::new(0.0, 1.0, 300, Easing::EaseIn);
    let anim2 = anim1;
    assert_eq!(anim1.duration_ms, anim2.duration_ms);
    assert_eq!(anim1.easing, anim2.easing);
}

#[test]
fn test_transition_fade_in() {
    let anim = transitions::fade_in(200);
    assert_eq!(anim.start_value, 0.0);
    assert_eq!(anim.end_value, 1.0);
    assert_eq!(anim.duration_ms, 200);
}

#[test]
fn test_transition_fade_out() {
    let anim = transitions::fade_out(200);
    assert_eq!(anim.start_value, 1.0);
    assert_eq!(anim.end_value, 0.0);
    assert_eq!(anim.duration_ms, 200);
}

#[test]
fn test_transition_slide_in_left() {
    let anim = transitions::slide_in_left(100.0, 300);
    assert_eq!(anim.start_value, -100.0);
    assert_eq!(anim.end_value, 0.0);
}

#[test]
fn test_transition_slide_in_right() {
    let anim = transitions::slide_in_right(100.0, 300);
    assert_eq!(anim.start_value, 100.0);
    assert_eq!(anim.end_value, 0.0);
}

#[test]
fn test_transition_slide_in_up() {
    let anim = transitions::slide_in_up(100.0, 300);
    assert_eq!(anim.start_value, 100.0);
    assert_eq!(anim.end_value, 0.0);
}

#[test]
fn test_transition_slide_in_down() {
    let anim = transitions::slide_in_down(100.0, 300);
    assert_eq!(anim.start_value, -100.0);
    assert_eq!(anim.end_value, 0.0);
}

#[test]
fn test_transition_scale_in() {
    let anim = transitions::scale_in(250);
    assert_eq!(anim.start_value, 0.0);
    assert_eq!(anim.end_value, 1.0);
    assert_eq!(anim.easing, Easing::Spring);
}

#[test]
fn test_transition_scale_out() {
    let anim = transitions::scale_out(200);
    assert_eq!(anim.start_value, 1.0);
    assert_eq!(anim.end_value, 0.0);
}

#[test]
fn test_transition_hover_grow() {
    let anim = transitions::hover_grow(150);
    assert_eq!(anim.start_value, 1.0);
    assert_eq!(anim.end_value, 1.05);
}

#[test]
fn test_transition_hover_shrink() {
    let anim = transitions::hover_shrink(150);
    assert_eq!(anim.start_value, 1.05);
    assert_eq!(anim.end_value, 1.0);
}

#[test]
fn test_transition_press() {
    let anim = transitions::press(100);
    assert_eq!(anim.start_value, 1.0);
    assert_eq!(anim.end_value, 0.95);
}

#[test]
fn test_transition_release() {
    let anim = transitions::release(150);
    assert_eq!(anim.start_value, 0.95);
    assert_eq!(anim.end_value, 1.0);
    assert_eq!(anim.easing, Easing::Spring);
}

#[test]
fn test_transition_pulse_glow() {
    let anim = transitions::pulse_glow(400);
    assert_eq!(anim.start_value, 0.6);
    assert_eq!(anim.end_value, 1.0);
}

#[test]
fn test_transition_spinner_rotation() {
    let anim = transitions::spinner_rotation(1000);
    assert_eq!(anim.start_value, 0.0);
    assert_eq!(anim.end_value, 360.0);
    assert_eq!(anim.easing, Easing::Linear);
}

#[test]
fn test_duration_constants() {
    assert_eq!(transitions::DURATION_FAST, 150);
    assert_eq!(transitions::DURATION_NORMAL, 250);
    assert_eq!(transitions::DURATION_SLOW, 400);
    assert_eq!(transitions::DURATION_VERY_SLOW, 600);
}

#[test]
fn test_timing_constants() {
    assert_eq!(timing::TARGET_FPS, 60);
    assert_eq!(timing::FRAME_BUDGET_MS, 16);
}

#[test]
fn test_timing_ms_to_frames() {
    assert_eq!(timing::ms_to_frames(1000, 60), 60);
    assert_eq!(timing::ms_to_frames(500, 60), 30);
    assert_eq!(timing::ms_to_frames(0, 60), 0);
}

#[test]
fn test_timing_frames_to_ms() {
    assert_eq!(timing::frames_to_ms(60, 60), 1000);
    assert_eq!(timing::frames_to_ms(30, 60), 500);
    assert_eq!(timing::frames_to_ms(0, 60), 0);
}

#[test]
fn test_timing_should_update_animation() {
    let now = timing::current_time();
    assert!(!timing::should_update_animation(now, u64::MAX));
}
