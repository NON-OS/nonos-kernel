extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct FocusableElement {
    pub id: String,
    pub tag: String,
    pub tabindex: i32,
    pub naturally_focusable: bool,
}

pub fn build_tab_order(elements: &[FocusableElement]) -> Vec<usize> {
    let mut positive: Vec<(i32, usize)> = Vec::new();
    let mut zero: Vec<usize> = Vec::new();
    for (i, el) in elements.iter().enumerate() {
        if el.tabindex < 0 { continue; }
        if el.tabindex > 0 { positive.push((el.tabindex, i)); }
        else if el.naturally_focusable || el.tabindex == 0 { zero.push(i); }
    }
    positive.sort_by_key(|(tab, _)| *tab);
    let mut order: Vec<usize> = positive.iter().map(|(_, i)| *i).collect();
    order.extend(zero);
    order
}
