extern crate alloc;
use alloc::vec::Vec;
use super::computed::ComputedStyle;
use super::defaults::default_style;
use super::inherit::inherit_from_parent;
use super::apply::apply_declaration;
use super::super::parser::{Stylesheet, Declaration};
use super::super::selector::{Specificity, matches_selector};
use super::super::selector::match_node::NodeInfo;

pub fn resolve_style(
    node: &NodeInfo,
    parent: Option<&ComputedStyle>,
    stylesheets: &[Stylesheet],
    inline_decls: &[Declaration],
) -> ComputedStyle {
    let mut style = default_style();
    let mut matched = collect_matching_rules(node, stylesheets);
    matched.sort_by_key(|(spec, idx, imp)| (*imp, *spec, *idx));

    for (_, _, _, decl) in &matched {
        apply_declaration(&mut style, decl);
    }
    for decl in inline_decls {
        apply_declaration(&mut style, decl);
    }
    if let Some(parent) = parent {
        inherit_from_parent(&mut style, parent);
    }
    style
}

fn collect_matching_rules<'a>(
    node: &NodeInfo,
    stylesheets: &'a [Stylesheet],
) -> Vec<(Specificity, usize, bool, &'a Declaration)> {
    let mut result = Vec::new();
    let mut idx = 0;
    for sheet in stylesheets {
        for rule in &sheet.rules {
            for selector in &rule.selectors {
                if matches_selector(node, selector) {
                    let spec = Specificity::of(selector);
                    for decl in &rule.declarations {
                        result.push((spec, idx, decl.important, decl));
                        idx += 1;
                    }
                }
            }
        }
    }
    result
}
