extern crate alloc;
use super::super::tokenizer::CssToken;
use super::parse_declaration::parse_declarations_from_tokens;
use super::parse_selector::parse_selector;
use super::stylesheet::Rule;
use alloc::string::String;
use alloc::vec::Vec;

pub fn parse_media_block(tokens: &[CssToken], start: usize) -> (Vec<Rule>, usize) {
    let mut i = start;
    let mut query_parts = Vec::new();

    while i < tokens.len() && !matches!(tokens[i], CssToken::OpenBrace) {
        if let CssToken::Ident(ref s) = tokens[i] {
            query_parts.push(s.clone());
        }
        i += 1;
    }

    if i >= tokens.len() {
        return (Vec::new(), tokens.len());
    }

    let media_query: String = query_parts.join(" ");
    i += 1;

    let mut rules = Vec::new();
    let mut depth = 1u32;

    while i < tokens.len() && depth > 0 {
        if matches!(tokens[i], CssToken::CloseBrace) {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        if matches!(tokens[i], CssToken::OpenBrace) {
            depth += 1;
        }

        let (rule, next) = parse_inner_rule(tokens, i, &media_query);
        if let Some(r) = rule {
            rules.push(r);
        }
        i = if next > i { next } else { i + 1 };
    }

    (rules, if i < tokens.len() { i + 1 } else { i })
}

fn parse_inner_rule(tokens: &[CssToken], start: usize, media: &str) -> (Option<Rule>, usize) {
    let brace = tokens[start..].iter().position(|t| matches!(t, CssToken::OpenBrace));
    let brace_pos = match brace {
        Some(p) => start + p,
        None => return (None, tokens.len()),
    };

    let selectors = parse_selector(&tokens[start..brace_pos]);
    let mut close = brace_pos + 1;
    let mut depth = 1u32;
    while close < tokens.len() && depth > 0 {
        match tokens[close] {
            CssToken::OpenBrace => depth += 1,
            CssToken::CloseBrace => depth -= 1,
            _ => {}
        }
        if depth > 0 {
            close += 1;
        }
    }

    let decls = parse_declarations_from_tokens(&tokens[brace_pos + 1..close]);
    if selectors.is_empty() {
        return (None, close + 1);
    }

    let mut rule = Rule::new(selectors, decls);
    rule.media_query = Some(String::from(media));
    (Some(rule), close + 1)
}
