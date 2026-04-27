use super::super::super::css::cascade::resolve_length;
use super::super::super::css::types::CssValue;
use super::super::types::LayoutBox;

pub fn calculate_block_height(layout_box: &mut LayoutBox) {
    let style = &layout_box.style;

    match &style.height {
        CssValue::Auto | CssValue::None => {
            layout_box.dimensions.content.height = layout_box.content_height();
        }
        other => {
            let resolved = resolve_length(other, 16.0, 0.0, 0.0);
            layout_box.dimensions.content.height = clamp_height(resolved, style);
        }
    }
}

fn clamp_height(h: f32, style: &super::super::super::css::cascade::ComputedStyle) -> f32 {
    let min = resolve_length(&style.min_height, 16.0, 0.0, 0.0);
    let max = match &style.max_height {
        CssValue::None | CssValue::Auto => f32::MAX,
        other => resolve_length(other, 16.0, 0.0, 0.0),
    };
    h.max(min).min(max)
}
