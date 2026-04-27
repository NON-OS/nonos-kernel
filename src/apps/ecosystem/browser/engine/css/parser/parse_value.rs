extern crate alloc;
use super::super::color::parse_color;
use super::super::types::{CssValue, Unit};
use alloc::string::String;

pub fn parse_css_value(input: &str) -> CssValue {
    let s = input.trim();

    match s.to_ascii_lowercase().as_str() {
        "auto" => return CssValue::Auto,
        "none" => return CssValue::None,
        "inherit" => return CssValue::Inherit,
        "initial" => return CssValue::Initial,
        _ => {}
    }

    if let Some(color) = parse_color(s) {
        return CssValue::Color(color);
    }

    if let Some(length) = parse_length(s) {
        return length;
    }

    if let Some(pct) = s.strip_suffix('%') {
        if let Ok(v) = pct.trim().parse::<f32>() {
            return CssValue::Percentage(v);
        }
    }

    if let Ok(v) = s.parse::<f32>() {
        return CssValue::Number(v);
    }

    CssValue::Keyword(String::from(s))
}

fn parse_length(s: &str) -> Option<CssValue> {
    let units: &[(&str, Unit)] = &[
        ("px", Unit::Px),
        ("em", Unit::Em),
        ("rem", Unit::Rem),
        ("vw", Unit::Vw),
        ("vh", Unit::Vh),
        ("pt", Unit::Pt),
    ];

    for (suffix, unit) in units {
        if let Some(num_str) = s.strip_suffix(suffix) {
            if let Ok(v) = num_str.trim().parse::<f32>() {
                return Some(CssValue::Length(v, *unit));
            }
        }
    }
    None
}
