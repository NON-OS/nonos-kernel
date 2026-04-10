extern crate alloc;
use super::stylesheet::{Stylesheet, Rule};
use super::parse_selector::parse_selector;
use super::parse_declaration::parse_declarations_from_tokens;
use super::parse_media::parse_media_block;
use super::super::tokenizer::{tokenize, CssToken};

pub fn parse_stylesheet(input: &str) -> Stylesheet {
    let tokens = tokenize(input);
    let mut stylesheet = Stylesheet::new();
    let mut i = 0;

    while i < tokens.len() {
        if tokens[i].is_whitespace() {
            i += 1;
            continue;
        }
        if let CssToken::AtKeyword(ref kw) = tokens[i] {
            if kw.eq_ignore_ascii_case("media") {
                let (rules, next) = parse_media_block(&tokens, i + 1);
                stylesheet.rules.extend(rules);
                i = next;
                continue;
            }
            i = skip_to_after_block(&tokens, i);
            continue;
        }
        let (rule, next) = parse_one_rule(&tokens, i);
        if let Some(r) = rule {
            stylesheet.rules.push(r);
        }
        i = if next > i { next } else { i + 1 };
    }
    stylesheet
}

fn parse_one_rule(tokens: &[CssToken], start: usize) -> (Option<Rule>, usize) {
    let brace = tokens[start..].iter().position(|t| matches!(t, CssToken::OpenBrace));
    let brace_pos = match brace {
        Some(p) => start + p,
        None => return (None, tokens.len()),
    };

    let selector_tokens = &tokens[start..brace_pos];
    let selectors = parse_selector(selector_tokens);

    let close = find_close_brace(tokens, brace_pos + 1);
    let decl_tokens = &tokens[brace_pos + 1..close];
    let declarations = parse_declarations_from_tokens(decl_tokens);

    if selectors.is_empty() {
        return (None, close + 1);
    }
    (Some(Rule::new(selectors, declarations)), close + 1)
}

fn find_close_brace(tokens: &[CssToken], start: usize) -> usize {
    let mut depth = 1u32;
    let mut i = start;
    while i < tokens.len() && depth > 0 {
        match tokens[i] {
            CssToken::OpenBrace => depth += 1,
            CssToken::CloseBrace => depth -= 1,
            _ => {}
        }
        if depth > 0 { i += 1; }
    }
    i
}

fn skip_to_after_block(tokens: &[CssToken], start: usize) -> usize {
    let brace = tokens[start..].iter().position(|t| matches!(t, CssToken::OpenBrace));
    match brace {
        Some(p) => find_close_brace(tokens, start + p + 1) + 1,
        None => tokens.len(),
    }
}
