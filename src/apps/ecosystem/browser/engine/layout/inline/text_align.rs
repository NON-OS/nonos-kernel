use super::super::super::css::cascade::TextAlign;
use super::line_box::LineBox;

pub fn apply_text_alignment(line: &mut LineBox, container_width: f32, align: TextAlign) {
    match align {
        TextAlign::Left => {}
        TextAlign::Center => shift_fragments(line, (container_width - line.width) / 2.0),
        TextAlign::Right => shift_fragments(line, container_width - line.width),
        TextAlign::Justify => justify_fragments(line, container_width),
    }
}

fn shift_fragments(line: &mut LineBox, offset: f32) {
    if offset <= 0.0 {
        return;
    }
    for fragment in &mut line.fragments {
        fragment.x += offset;
    }
}

fn justify_fragments(line: &mut LineBox, container_width: f32) {
    let gap_count = line.fragments.len().saturating_sub(1);
    if gap_count == 0 {
        return;
    }
    let total_text_width: f32 = line.fragments.iter().map(|f| f.width).sum();
    let extra_space = container_width - total_text_width;
    if extra_space <= 0.0 {
        return;
    }
    let gap = extra_space / gap_count as f32;
    let mut x = 0.0f32;
    for fragment in &mut line.fragments {
        fragment.x = x;
        x += fragment.width + gap;
    }
}
