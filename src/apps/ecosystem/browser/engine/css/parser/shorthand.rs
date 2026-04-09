extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use super::stylesheet::Declaration;
use super::parse_value::parse_css_value;

pub fn expand_shorthand(decl: &Declaration) -> Vec<Declaration> {
    match decl.property.as_str() {
        "margin" => expand_box_shorthand(&decl.property, &decl.value, decl.important),
        "padding" => expand_box_shorthand(&decl.property, &decl.value, decl.important),
        _ => alloc::vec![decl.clone()],
    }
}

fn expand_box_shorthand(
    prefix: &str,
    value: &super::super::types::CssValue,
    important: bool,
) -> Vec<Declaration> {
    let val_str = css_value_to_string(value);
    let parts: Vec<&str> = val_str.split_whitespace().collect();
    let (top, right, bottom, left) = match parts.len() {
        1 => (parts[0], parts[0], parts[0], parts[0]),
        2 => (parts[0], parts[1], parts[0], parts[1]),
        3 => (parts[0], parts[1], parts[2], parts[1]),
        4 => (parts[0], parts[1], parts[2], parts[3]),
        _ => return alloc::vec![Declaration::new(String::from(prefix), value.clone())],
    };

    let sides = [
        (alloc::format!("{}-top", prefix), top),
        (alloc::format!("{}-right", prefix), right),
        (alloc::format!("{}-bottom", prefix), bottom),
        (alloc::format!("{}-left", prefix), left),
    ];

    sides.iter().map(|(prop, val)| {
        let mut d = Declaration::new(prop.clone(), parse_css_value(val));
        if important { d = d.important(); }
        d
    }).collect()
}

fn css_value_to_string(value: &super::super::types::CssValue) -> String {
    use super::super::types::CssValue;
    match value {
        CssValue::Length(v, u) => alloc::format!("{}{}", v, unit_str(u)),
        CssValue::Number(v) => alloc::format!("{}", v),
        CssValue::Percentage(v) => alloc::format!("{}%", v),
        CssValue::Keyword(s) => s.clone(),
        CssValue::Auto => String::from("auto"),
        CssValue::None => String::from("none"),
        _ => String::new(),
    }
}

fn unit_str(u: &super::super::types::Unit) -> &'static str {
    use super::super::types::Unit;
    match u {
        Unit::Px => "px",
        Unit::Em => "em",
        Unit::Rem => "rem",
        Unit::Percent => "%",
        Unit::Vw => "vw",
        Unit::Vh => "vh",
        Unit::Pt => "pt",
    }
}
