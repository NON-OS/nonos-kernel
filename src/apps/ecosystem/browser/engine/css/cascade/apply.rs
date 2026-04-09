use super::computed::{ComputedStyle, TextAlign};
use super::super::parser::Declaration;
use super::super::types::CssValue;
use super::super::properties::*;
use super::super::color::parse_color;

pub fn apply_declaration(style: &mut ComputedStyle, decl: &Declaration) {
    match decl.property.as_str() {
        "display" => style.display = keyword_to_display(&decl.value),
        "position" => style.position = keyword_to_position(&decl.value),
        "width" => style.width = decl.value.clone(),
        "height" => style.height = decl.value.clone(),
        "min-width" => style.min_width = decl.value.clone(),
        "max-width" => style.max_width = decl.value.clone(),
        "min-height" => style.min_height = decl.value.clone(),
        "max-height" => style.max_height = decl.value.clone(),
        "margin-top" => style.margin_top = decl.value.clone(),
        "margin-right" => style.margin_right = decl.value.clone(),
        "margin-bottom" => style.margin_bottom = decl.value.clone(),
        "margin-left" => style.margin_left = decl.value.clone(),
        "padding-top" => style.padding_top = decl.value.clone(),
        "padding-right" => style.padding_right = decl.value.clone(),
        "padding-bottom" => style.padding_bottom = decl.value.clone(),
        "padding-left" => style.padding_left = decl.value.clone(),
        "color" => style.color = extract_color(&decl.value),
        "background-color" => style.background_color = extract_color(&decl.value),
        "font-size" => style.font_size = decl.value.clone(),
        "font-weight" => style.font_weight = keyword_to_font_weight(&decl.value),
        "text-align" => style.text_align = keyword_to_text_align(&decl.value),
        "visibility" => style.visibility = keyword_to_visibility(&decl.value),
        "overflow" => style.overflow = keyword_to_overflow(&decl.value),
        "float" => style.float = keyword_to_float(&decl.value),
        "clear" => style.clear = keyword_to_clear(&decl.value),
        "flex-direction" => style.flex_direction = keyword_to_flex_dir(&decl.value),
        "justify-content" => style.justify_content = keyword_to_justify(&decl.value),
        "align-items" => style.align_items = keyword_to_align(&decl.value),
        "top" => style.top = decl.value.clone(),
        "right" => style.right = decl.value.clone(),
        "bottom" => style.bottom = decl.value.clone(),
        "left" => style.left = decl.value.clone(),
        "z-index" => style.z_index = decl.value.clone(),
        "opacity" => if let CssValue::Number(v) = decl.value { style.opacity = v; },
        "flex-grow" => if let CssValue::Number(v) = decl.value { style.flex_grow = v; },
        "flex-shrink" => if let CssValue::Number(v) = decl.value { style.flex_shrink = v; },
        "flex-basis" => style.flex_basis = decl.value.clone(),
        _ => {}
    }
}

fn extract_color(val: &CssValue) -> Option<super::super::types::CssColor> {
    match val {
        CssValue::Color(c) => Some(*c),
        CssValue::Keyword(s) => parse_color(s),
        _ => None,
    }
}

fn keyword_str(val: &CssValue) -> &str {
    match val {
        CssValue::Keyword(s) => s.as_str(),
        _ => "",
    }
}

fn keyword_to_display(v: &CssValue) -> Display { Display::from_str(keyword_str(v)) }
fn keyword_to_position(v: &CssValue) -> Position { Position::from_str(keyword_str(v)) }
fn keyword_to_font_weight(v: &CssValue) -> FontWeight { FontWeight::from_str(keyword_str(v)) }
fn keyword_to_text_align(v: &CssValue) -> TextAlign { TextAlign::from_str(keyword_str(v)) }
fn keyword_to_visibility(v: &CssValue) -> Visibility { Visibility::from_str(keyword_str(v)) }
fn keyword_to_overflow(v: &CssValue) -> Overflow { Overflow::from_str(keyword_str(v)) }
fn keyword_to_float(v: &CssValue) -> Float { Float::from_str(keyword_str(v)) }
fn keyword_to_clear(v: &CssValue) -> Clear { Clear::from_str(keyword_str(v)) }
fn keyword_to_flex_dir(v: &CssValue) -> FlexDirection { FlexDirection::from_str(keyword_str(v)) }
fn keyword_to_justify(v: &CssValue) -> JustifyContent { JustifyContent::from_str(keyword_str(v)) }
fn keyword_to_align(v: &CssValue) -> AlignItems { AlignItems::from_str(keyword_str(v)) }
