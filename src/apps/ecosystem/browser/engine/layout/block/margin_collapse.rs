pub fn collapse_margins(prev_margin_bottom: f32, current_margin_top: f32) -> f32 {
    if prev_margin_bottom >= 0.0 && current_margin_top >= 0.0 {
        return max_f32(prev_margin_bottom, current_margin_top);
    }
    if prev_margin_bottom < 0.0 && current_margin_top < 0.0 {
        return min_f32(prev_margin_bottom, current_margin_top);
    }
    prev_margin_bottom + current_margin_top
}

fn max_f32(a: f32, b: f32) -> f32 {
    if a > b { a } else { b }
}

fn min_f32(a: f32, b: f32) -> f32 {
    if a < b { a } else { b }
}
