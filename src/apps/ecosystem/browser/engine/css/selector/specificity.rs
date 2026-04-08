use super::types::{Selector, SimpleSelector};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Specificity {
    pub inline: u32,
    pub ids: u32,
    pub classes: u32,
    pub types: u32,
}

impl Specificity {
    pub fn zero() -> Self {
        Self { inline: 0, ids: 0, classes: 0, types: 0 }
    }

    pub fn inline_style() -> Self {
        Self { inline: 1, ids: 0, classes: 0, types: 0 }
    }

    pub fn of(selector: &Selector) -> Self {
        let mut s = Self::zero();
        accumulate(&mut s, selector);
        s
    }
}

fn accumulate(s: &mut Specificity, selector: &Selector) {
    match selector {
        Selector::Simple(simple) => accumulate_simple(s, simple),
        Selector::Compound(parts) => {
            for part in parts {
                accumulate_simple(s, part);
            }
        }
        Selector::Descendant(left, right)
        | Selector::Child(left, right)
        | Selector::Adjacent(left, right)
        | Selector::General(left, right) => {
            accumulate(s, left);
            accumulate(s, right);
        }
        Selector::Universal => {}
    }
}

fn accumulate_simple(s: &mut Specificity, simple: &SimpleSelector) {
    if simple.id.is_some() {
        s.ids += 1;
    }
    s.classes += simple.classes.len() as u32;
    s.classes += simple.pseudo_classes.len() as u32;
    s.classes += simple.attributes.len() as u32;
    if simple.tag.is_some() {
        s.types += 1;
    }
}
