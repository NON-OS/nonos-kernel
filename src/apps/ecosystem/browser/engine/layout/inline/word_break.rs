extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use super::line_box::LineBox;

pub fn break_into_lines(
    text: &str,
    container_width: f32,
    char_width: f32,
    line_height: f32,
    start_y: f32,
    node_index: Option<u32>,
) -> Vec<LineBox> {
    let mut lines: Vec<LineBox> = Vec::new();
    let mut current_line = LineBox::new(start_y, line_height);
    let words = split_words(text);

    for word in &words {
        let word_width = word.len() as f32 * char_width;

        if word_width > current_line.remaining_width(container_width) && !current_line.fragments.is_empty() {
            let next_y = current_line.y + current_line.height;
            lines.push(current_line);
            current_line = LineBox::new(next_y, line_height);
        }

        current_line.add_fragment(String::from(*word), char_width, node_index);
    }

    if !current_line.fragments.is_empty() {
        lines.push(current_line);
    }

    lines
}

fn split_words(text: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() {
            if let Some(s) = start {
                words.push(&text[s..i]);
                start = None;
            }
            words.push(" ");
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        words.push(&text[s..]);
    }
    words
}
