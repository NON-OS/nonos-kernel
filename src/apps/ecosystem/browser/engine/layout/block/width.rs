use super::super::types::{LayoutBox, Dimensions};
use super::super::super::css::types::CssValue;
use super::super::super::css::cascade::resolve_length;

pub fn calculate_block_width(layout_box: &mut LayoutBox, containing_width: f32) {
    let style = &layout_box.style;
    let parent_font = 16.0;
    let vw = containing_width;
    let vh = 0.0;

    let margin_left = resolve_or_zero(&style.margin_left, parent_font, vw, vh);
    let margin_right = resolve_or_zero(&style.margin_right, parent_font, vw, vh);
    let border_left = resolve_or_zero(&style.border_top_width, parent_font, vw, vh);
    let border_right = resolve_or_zero(&style.border_right_width, parent_font, vw, vh);
    let padding_left = resolve_or_zero(&style.padding_left, parent_font, vw, vh);
    let padding_right = resolve_or_zero(&style.padding_right, parent_font, vw, vh);

    let total_fixed = margin_left + margin_right + border_left + border_right + padding_left + padding_right;

    let width = match &style.width {
        CssValue::Auto | CssValue::None => containing_width - total_fixed,
        other => resolve_or_zero(other, parent_font, vw, vh),
    };

    layout_box.dimensions.content.width = clamp_width(width, style, parent_font, vw, vh);
    layout_box.dimensions.margin.left = margin_left;
    layout_box.dimensions.margin.right = margin_right;
    layout_box.dimensions.border.left = border_left;
    layout_box.dimensions.border.right = border_right;
    layout_box.dimensions.padding.left = padding_left;
    layout_box.dimensions.padding.right = padding_right;

    auto_margin_centering(layout_box, containing_width);
}

fn auto_margin_centering(layout_box: &mut LayoutBox, containing_width: f32) {
    if !layout_box.style.margin_left.is_auto() || !layout_box.style.margin_right.is_auto() {
        return;
    }
    let used = layout_box.dimensions.content.width + layout_box.dimensions.total_horizontal()
        - layout_box.dimensions.margin.left - layout_box.dimensions.margin.right;
    let remaining = containing_width - used;
    if remaining > 0.0 {
        layout_box.dimensions.margin.left = remaining / 2.0;
        layout_box.dimensions.margin.right = remaining / 2.0;
    }
}

fn clamp_width(w: f32, style: &super::super::super::css::cascade::ComputedStyle, fs: f32, vw: f32, vh: f32) -> f32 {
    let min = resolve_or_zero(&style.min_width, fs, vw, vh);
    let max = match &style.max_width {
        CssValue::None | CssValue::Auto => f32::MAX,
        other => resolve_or_zero(other, fs, vw, vh),
    };
    w.max(min).min(max)
}

fn resolve_or_zero(val: &CssValue, fs: f32, vw: f32, vh: f32) -> f32 {
    resolve_length(val, fs, vw, vh)
}
