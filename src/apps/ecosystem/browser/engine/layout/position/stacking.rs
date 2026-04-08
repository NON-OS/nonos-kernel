use super::super::types::LayoutBox;
use super::super::super::css::types::CssValue;

pub fn sort_by_z_index(children: &mut [LayoutBox]) {
    children.sort_by(|a, b| {
        let za = z_index_value(&a.style.z_index);
        let zb = z_index_value(&b.style.z_index);
        za.cmp(&zb)
    });
}

fn z_index_value(val: &CssValue) -> i32 {
    match val {
        CssValue::Number(n) => *n as i32,
        _ => 0,
    }
}
