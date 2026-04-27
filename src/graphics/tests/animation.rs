use crate::graphics::animation::*;
use crate::test::framework::TestResult;

pub(crate) fn test_easing_values() -> TestResult {
    if Easing::Linear != Easing::Linear {
        return TestResult::Fail;
    }
    if Easing::EaseIn != Easing::EaseIn {
        return TestResult::Fail;
    }
    if Easing::EaseOut != Easing::EaseOut {
        return TestResult::Fail;
    }
    if Easing::EaseInOut != Easing::EaseInOut {
        return TestResult::Fail;
    }
    if Easing::Spring != Easing::Spring {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_easing_inequality() -> TestResult {
    if Easing::Linear == Easing::EaseIn {
        return TestResult::Fail;
    }
    if Easing::EaseIn == Easing::EaseOut {
        return TestResult::Fail;
    }
    if Easing::EaseOut == Easing::EaseInOut {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_easing_linear() -> TestResult {
    if apply_easing(0.0, Easing::Linear) != 0.0 {
        return TestResult::Fail;
    }
    if apply_easing(0.5, Easing::Linear) != 0.5 {
        return TestResult::Fail;
    }
    if apply_easing(1.0, Easing::Linear) != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_easing_clamps_input() -> TestResult {
    if apply_easing(-1.0, Easing::Linear) != 0.0 {
        return TestResult::Fail;
    }
    if apply_easing(2.0, Easing::Linear) != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_easing_ease_in() -> TestResult {
    let start = apply_easing(0.0, Easing::EaseIn);
    let middle = apply_easing(0.5, Easing::EaseIn);
    let end = apply_easing(1.0, Easing::EaseIn);

    if start != 0.0 {
        return TestResult::Fail;
    }
    if !(middle < 0.5) {
        return TestResult::Fail;
    }
    if end != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_easing_ease_out() -> TestResult {
    let start = apply_easing(0.0, Easing::EaseOut);
    let middle = apply_easing(0.5, Easing::EaseOut);
    let end = apply_easing(1.0, Easing::EaseOut);

    if start != 0.0 {
        return TestResult::Fail;
    }
    if !(middle > 0.5) {
        return TestResult::Fail;
    }
    if end != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_easing_ease_in_out() -> TestResult {
    let start = apply_easing(0.0, Easing::EaseInOut);
    let middle = apply_easing(0.5, Easing::EaseInOut);
    let end = apply_easing(1.0, Easing::EaseInOut);

    if start != 0.0 {
        return TestResult::Fail;
    }
    if !((middle - 0.5).abs() < 0.01) {
        return TestResult::Fail;
    }
    if end != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_easing_spring() -> TestResult {
    let start = apply_easing(0.0, Easing::Spring);
    let end = apply_easing(1.0, Easing::Spring);

    if start != 0.0 {
        return TestResult::Fail;
    }
    if end != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interpolate() -> TestResult {
    if interpolate(0.0, 100.0, 0.0) != 0.0 {
        return TestResult::Fail;
    }
    if interpolate(0.0, 100.0, 0.5) != 50.0 {
        return TestResult::Fail;
    }
    if interpolate(0.0, 100.0, 1.0) != 100.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interpolate_negative() -> TestResult {
    if interpolate(-50.0, 50.0, 0.5) != 0.0 {
        return TestResult::Fail;
    }
    if interpolate(100.0, 0.0, 0.5) != 50.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interpolate_u32() -> TestResult {
    if interpolate_u32(0, 100, 0.0) != 0 {
        return TestResult::Fail;
    }
    if interpolate_u32(0, 100, 0.5) != 50 {
        return TestResult::Fail;
    }
    if interpolate_u32(0, 100, 1.0) != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interpolate_u32_boundary() -> TestResult {
    if interpolate_u32(0, 100, -1.0) != 0 {
        return TestResult::Fail;
    }
    if interpolate_u32(0, 100, 2.0) != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interpolate_color() -> TestResult {
    let black = 0xFF000000u32;
    let white = 0xFFFFFFFFu32;

    let start = interpolate_color(black, white, 0.0);
    let end = interpolate_color(black, white, 1.0);

    if start != black {
        return TestResult::Fail;
    }
    if end != white {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interpolate_color_midpoint() -> TestResult {
    let black = 0xFF000000u32;
    let white = 0xFFFFFFFFu32;

    let mid = interpolate_color(black, white, 0.5);
    let r = (mid >> 16) & 0xFF;
    let g = (mid >> 8) & 0xFF;
    let b = mid & 0xFF;

    if !((r as i32 - 127).abs() <= 1) {
        return TestResult::Fail;
    }
    if !((g as i32 - 127).abs() <= 1) {
        return TestResult::Fail;
    }
    if !((b as i32 - 127).abs() <= 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interpolate_color_alpha() -> TestResult {
    let transparent = 0x00FF0000u32;
    let opaque = 0xFFFF0000u32;

    let mid = interpolate_color(transparent, opaque, 0.5);
    let a = (mid >> 24) & 0xFF;

    if !((a as i32 - 127).abs() <= 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_status_values() -> TestResult {
    if AnimationStatus::Idle != AnimationStatus::Idle {
        return TestResult::Fail;
    }
    if AnimationStatus::Running != AnimationStatus::Running {
        return TestResult::Fail;
    }
    if AnimationStatus::Completed != AnimationStatus::Completed {
        return TestResult::Fail;
    }
    if AnimationStatus::Paused != AnimationStatus::Paused {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_status_inequality() -> TestResult {
    if AnimationStatus::Idle == AnimationStatus::Running {
        return TestResult::Fail;
    }
    if AnimationStatus::Running == AnimationStatus::Completed {
        return TestResult::Fail;
    }
    if AnimationStatus::Completed == AnimationStatus::Paused {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_new() -> TestResult {
    let anim = Animation::new(0.0, 100.0, 500, Easing::EaseOut);
    if anim.start_value != 0.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 100.0 {
        return TestResult::Fail;
    }
    if anim.duration_ms != 500 {
        return TestResult::Fail;
    }
    if anim.easing != Easing::EaseOut {
        return TestResult::Fail;
    }
    if anim.status != AnimationStatus::Idle {
        return TestResult::Fail;
    }
    if anim.delay_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_with_delay() -> TestResult {
    let anim = Animation::new(0.0, 1.0, 300, Easing::Linear).with_delay(100);
    if anim.delay_ms != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_start() -> TestResult {
    let mut anim = Animation::new(0.0, 1.0, 300, Easing::Linear);
    anim.start(1000);
    if anim.status != AnimationStatus::Running {
        return TestResult::Fail;
    }
    if anim.started_at != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_progress_idle() -> TestResult {
    let anim = Animation::new(0.0, 1.0, 300, Easing::Linear);
    if anim.progress(1000) != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_progress_completed() -> TestResult {
    let mut anim = Animation::new(0.0, 1.0, 300, Easing::Linear);
    anim.complete();
    if anim.progress(1000) != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_progress_running() -> TestResult {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(0);
    if anim.progress(0) != 0.0 {
        return TestResult::Fail;
    }
    if anim.progress(50) != 0.5 {
        return TestResult::Fail;
    }
    if anim.progress(100) != 1.0 {
        return TestResult::Fail;
    }
    if anim.progress(200) != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_progress_with_delay() -> TestResult {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear).with_delay(50);
    anim.start(0);
    if anim.progress(0) != 0.0 {
        return TestResult::Fail;
    }
    if anim.progress(50) != 0.0 {
        return TestResult::Fail;
    }
    if anim.progress(100) != 0.5 {
        return TestResult::Fail;
    }
    if anim.progress(150) != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_current_value() -> TestResult {
    let mut anim = Animation::new(0.0, 100.0, 100, Easing::Linear);
    anim.start(0);
    if anim.current_value(0) != 0.0 {
        return TestResult::Fail;
    }
    if anim.current_value(50) != 50.0 {
        return TestResult::Fail;
    }
    if anim.current_value(100) != 100.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_is_complete() -> TestResult {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(0);
    if anim.is_complete(50) {
        return TestResult::Fail;
    }
    if !anim.is_complete(100) {
        return TestResult::Fail;
    }
    if !anim.is_complete(200) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_complete() -> TestResult {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(0);
    anim.complete();
    if anim.status != AnimationStatus::Completed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_reset() -> TestResult {
    let mut anim = Animation::new(0.0, 1.0, 100, Easing::Linear);
    anim.start(1000);
    anim.reset();
    if anim.status != AnimationStatus::Idle {
        return TestResult::Fail;
    }
    if anim.started_at != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_default() -> TestResult {
    let anim = Animation::default();
    if anim.start_value != 0.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.duration_ms != 300 {
        return TestResult::Fail;
    }
    if anim.easing != Easing::EaseOut {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animation_copy() -> TestResult {
    let anim1 = Animation::new(0.0, 1.0, 300, Easing::EaseIn);
    let anim2 = anim1;
    if anim1.duration_ms != anim2.duration_ms {
        return TestResult::Fail;
    }
    if anim1.easing != anim2.easing {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_fade_in() -> TestResult {
    let anim = transitions::fade_in(200);
    if anim.start_value != 0.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.duration_ms != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_fade_out() -> TestResult {
    let anim = transitions::fade_out(200);
    if anim.start_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 0.0 {
        return TestResult::Fail;
    }
    if anim.duration_ms != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_slide_in_left() -> TestResult {
    let anim = transitions::slide_in_left(100.0, 300);
    if anim.start_value != -100.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_slide_in_right() -> TestResult {
    let anim = transitions::slide_in_right(100.0, 300);
    if anim.start_value != 100.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_slide_in_up() -> TestResult {
    let anim = transitions::slide_in_up(100.0, 300);
    if anim.start_value != 100.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_slide_in_down() -> TestResult {
    let anim = transitions::slide_in_down(100.0, 300);
    if anim.start_value != -100.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_scale_in() -> TestResult {
    let anim = transitions::scale_in(250);
    if anim.start_value != 0.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.easing != Easing::Spring {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_scale_out() -> TestResult {
    let anim = transitions::scale_out(200);
    if anim.start_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_hover_grow() -> TestResult {
    let anim = transitions::hover_grow(150);
    if anim.start_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 1.05 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_hover_shrink() -> TestResult {
    let anim = transitions::hover_shrink(150);
    if anim.start_value != 1.05 {
        return TestResult::Fail;
    }
    if anim.end_value != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_press() -> TestResult {
    let anim = transitions::press(100);
    if anim.start_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 0.95 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_release() -> TestResult {
    let anim = transitions::release(150);
    if anim.start_value != 0.95 {
        return TestResult::Fail;
    }
    if anim.end_value != 1.0 {
        return TestResult::Fail;
    }
    if anim.easing != Easing::Spring {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_pulse_glow() -> TestResult {
    let anim = transitions::pulse_glow(400);
    if anim.start_value != 0.6 {
        return TestResult::Fail;
    }
    if anim.end_value != 1.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transition_spinner_rotation() -> TestResult {
    let anim = transitions::spinner_rotation(1000);
    if anim.start_value != 0.0 {
        return TestResult::Fail;
    }
    if anim.end_value != 360.0 {
        return TestResult::Fail;
    }
    if anim.easing != Easing::Linear {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_duration_constants() -> TestResult {
    if transitions::DURATION_FAST != 150 {
        return TestResult::Fail;
    }
    if transitions::DURATION_NORMAL != 250 {
        return TestResult::Fail;
    }
    if transitions::DURATION_SLOW != 400 {
        return TestResult::Fail;
    }
    if transitions::DURATION_VERY_SLOW != 600 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timing_constants() -> TestResult {
    if timing::TARGET_FPS != 60 {
        return TestResult::Fail;
    }
    if timing::FRAME_BUDGET_MS != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timing_ms_to_frames() -> TestResult {
    if timing::ms_to_frames(1000, 60) != 60 {
        return TestResult::Fail;
    }
    if timing::ms_to_frames(500, 60) != 30 {
        return TestResult::Fail;
    }
    if timing::ms_to_frames(0, 60) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timing_frames_to_ms() -> TestResult {
    if timing::frames_to_ms(60, 60) != 1000 {
        return TestResult::Fail;
    }
    if timing::frames_to_ms(30, 60) != 500 {
        return TestResult::Fail;
    }
    if timing::frames_to_ms(0, 60) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timing_should_update_animation() -> TestResult {
    let now = timing::current_time();
    if timing::should_update_animation(now, u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
