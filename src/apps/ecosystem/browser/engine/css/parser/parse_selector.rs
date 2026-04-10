extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use super::super::tokenizer::CssToken;
use super::super::selector::{Selector, SimpleSelector};

pub fn parse_selector(tokens: &[CssToken]) -> Vec<Selector> {
    let groups = split_by_comma(tokens);
    groups.into_iter().filter_map(|g| parse_single_selector(&g)).collect()
}

fn split_by_comma(tokens: &[CssToken]) -> Vec<Vec<CssToken>> {
    let mut groups = Vec::new();
    let mut current = Vec::new();
    for token in tokens {
        if matches!(token, CssToken::Comma) {
            if !current.is_empty() {
                groups.push(core::mem::take(&mut current));
            }
        } else {
            current.push(token.clone());
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

fn parse_single_selector(tokens: &[CssToken]) -> Option<Selector> {
    let stripped: Vec<&CssToken> = tokens.iter().filter(|t| !t.is_whitespace()).collect();
    if stripped.is_empty() {
        return None;
    }
    let mut i = 0;
    let mut result = parse_one_simple(&stripped, &mut i)?;

    while i < stripped.len() {
        let combinator = match stripped[i] {
            CssToken::Greater => { i += 1; "child" }
            CssToken::Plus => { i += 1; "adjacent" }
            CssToken::Tilde => { i += 1; "general" }
            _ => "descendant",
        };
        let right = parse_one_simple(&stripped, &mut i)?;
        result = match combinator {
            "child" => Selector::Child(Box::new(result), Box::new(right)),
            "adjacent" => Selector::Adjacent(Box::new(result), Box::new(right)),
            "general" => Selector::General(Box::new(result), Box::new(right)),
            _ => Selector::Descendant(Box::new(result), Box::new(right)),
        };
    }
    Some(result)
}

fn parse_one_simple(tokens: &[&CssToken], i: &mut usize) -> Option<Selector> {
    let mut simple = SimpleSelector::new();
    let mut any = false;

    while *i < tokens.len() {
        match tokens[*i] {
            CssToken::Ident(ref name) => { simple.tag = Some(name.clone()); *i += 1; any = true; }
            CssToken::Hash(ref id) => { simple.id = Some(id.clone()); *i += 1; any = true; }
            CssToken::Dot if *i + 1 < tokens.len() => {
                *i += 1;
                if let CssToken::Ident(ref cls) = tokens[*i] {
                    simple.classes.push(cls.clone()); *i += 1; any = true;
                }
            }
            CssToken::Star => { *i += 1; return Some(Selector::Universal); }
            CssToken::Colon if *i + 1 < tokens.len() => {
                *i += 1;
                if let CssToken::Ident(ref pseudo) = tokens[*i] {
                    simple.pseudo_classes.push(pseudo.clone()); *i += 1; any = true;
                }
            }
            _ => break,
        }
    }
    if any { Some(Selector::Simple(simple)) } else { None }
}
