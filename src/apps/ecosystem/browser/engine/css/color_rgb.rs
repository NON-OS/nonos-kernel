extern crate alloc;
use super::types::CssColor;

pub fn parse_rgb_function(s: &str) -> Option<CssColor> {
    let inner = extract_function_args(s)?;
    let parts: alloc::vec::Vec<&str> = inner.split(',').collect();
    match parts.len() {
        3 => {
            let r = parse_component(parts[0])?;
            let g = parse_component(parts[1])?;
            let b = parse_component(parts[2])?;
            Some(CssColor::rgb(r, g, b))
        }
        4 => {
            let r = parse_component(parts[0])?;
            let g = parse_component(parts[1])?;
            let b = parse_component(parts[2])?;
            let a = parse_alpha(parts[3])?;
            Some(CssColor::rgba(r, g, b, a))
        }
        _ => None,
    }
}

fn extract_function_args(s: &str) -> Option<&str> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close <= open {
        return None;
    }
    Some(s[open + 1..close].trim())
}

fn parse_component(s: &str) -> Option<u8> {
    let trimmed = s.trim();
    if let Some(pct) = trimmed.strip_suffix('%') {
        let val: f32 = pct.trim().parse().ok()?;
        return Some((val * 2.55) as u8);
    }
    trimmed.parse::<u8>().ok()
}

fn parse_alpha(s: &str) -> Option<u8> {
    let trimmed = s.trim();
    if let Some(pct) = trimmed.strip_suffix('%') {
        let val: f32 = pct.trim().parse().ok()?;
        return Some((val * 2.55) as u8);
    }
    let val: f32 = trimmed.parse().ok()?;
    Some((val * 255.0) as u8)
}
