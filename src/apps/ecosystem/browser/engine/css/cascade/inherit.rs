use super::computed::ComputedStyle;

pub fn inherit_from_parent(child: &mut ComputedStyle, parent: &ComputedStyle) {
    if child.color.is_none() {
        child.color = parent.color;
    }
    if matches!(child.font_size, super::super::types::CssValue::Inherit) {
        child.font_size = parent.font_size.clone();
    }
    child.font_weight = inherit_if_default(child.font_weight, parent.font_weight);
    child.font_style = inherit_if_default(child.font_style, parent.font_style);
    child.white_space = inherit_if_default(child.white_space, parent.white_space);
    child.text_align = inherit_if_default(child.text_align, parent.text_align);
    child.visibility = inherit_if_default(child.visibility, parent.visibility);
    if matches!(child.line_height, super::super::types::CssValue::Inherit) {
        child.line_height = parent.line_height.clone();
    }
}

fn inherit_if_default<T: Default + PartialEq + Copy>(child_val: T, parent_val: T) -> T {
    if child_val == T::default() {
        parent_val
    } else {
        child_val
    }
}
