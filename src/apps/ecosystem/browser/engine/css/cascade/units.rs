use super::super::types::{CssValue, Unit};

pub fn resolve_length(
    value: &CssValue,
    parent_font_size: f32,
    viewport_w: f32,
    viewport_h: f32,
) -> f32 {
    match value {
        CssValue::Length(v, unit) => {
            resolve_unit(*v, *unit, parent_font_size, viewport_w, viewport_h)
        }
        CssValue::Number(v) => *v,
        CssValue::Percentage(pct) => pct * parent_font_size / 100.0,
        _ => 0.0,
    }
}

pub fn resolve_length_against(
    value: &CssValue,
    base: f32,
    parent_font_size: f32,
    vw: f32,
    vh: f32,
) -> f32 {
    match value {
        CssValue::Length(v, unit) => resolve_unit(*v, *unit, parent_font_size, vw, vh),
        CssValue::Percentage(pct) => pct * base / 100.0,
        CssValue::Number(v) => *v,
        _ => 0.0,
    }
}

fn resolve_unit(value: f32, unit: Unit, parent_font_size: f32, vw: f32, vh: f32) -> f32 {
    match unit {
        Unit::Px => value,
        Unit::Em => value * parent_font_size,
        Unit::Rem => value * 16.0,
        Unit::Percent => value * parent_font_size / 100.0,
        Unit::Vw => value * vw / 100.0,
        Unit::Vh => value * vh / 100.0,
        Unit::Pt => value * 1.333,
    }
}
