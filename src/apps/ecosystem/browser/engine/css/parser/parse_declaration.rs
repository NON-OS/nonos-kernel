extern crate alloc;
use super::super::tokenizer::CssToken;
use super::parse_value::parse_css_value;
use super::stylesheet::Declaration;
use alloc::string::String;
use alloc::vec::Vec;

pub fn parse_inline_style(input: &str) -> Vec<Declaration> {
    let mut decls = Vec::new();
    for part in input.split(';') {
        let part = part.trim();
        if let Some((prop, val)) = part.split_once(':') {
            if let Some(decl) = parse_one_declaration(prop.trim(), val.trim()) {
                decls.push(decl);
            }
        }
    }
    decls
}

pub fn parse_declarations_from_tokens(tokens: &[CssToken]) -> Vec<Declaration> {
    let mut decls = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if let Some((decl, next)) = try_parse_declaration(tokens, i) {
            decls.push(decl);
            i = next;
        } else {
            i += 1;
        }
    }
    decls
}

fn try_parse_declaration(tokens: &[CssToken], start: usize) -> Option<(Declaration, usize)> {
    let mut i = skip_ws_tokens(tokens, start);
    let prop = match tokens.get(i)? {
        CssToken::Ident(name) => name.clone(),
        _ => return None,
    };
    i = skip_ws_tokens(tokens, i + 1);
    if !matches!(tokens.get(i), Some(CssToken::Colon)) {
        return None;
    }
    i += 1;
    let (val_str, important, end) = collect_value_tokens(tokens, i);
    let value = parse_css_value(&val_str);
    let mut decl = Declaration::new(prop.to_ascii_lowercase(), value);
    if important {
        decl = decl.important();
    }
    Some((decl, end))
}

fn collect_value_tokens(tokens: &[CssToken], start: usize) -> (String, bool, usize) {
    let mut parts = Vec::new();
    let mut i = start;
    let mut important = false;
    while i < tokens.len() && !matches!(tokens[i], CssToken::Semicolon | CssToken::CloseBrace) {
        if let CssToken::Ident(ref s) = tokens[i] {
            if s == "!important" || s == "important" {
                important = true;
            } else {
                parts.push(s.clone());
            }
        } else {
            parts.push(token_to_string(&tokens[i]));
        }
        i += 1;
    }
    if i < tokens.len() && matches!(tokens[i], CssToken::Semicolon) {
        i += 1;
    }
    (parts.join(" "), important, i)
}

fn skip_ws_tokens(tokens: &[CssToken], mut i: usize) -> usize {
    while i < tokens.len() && tokens[i].is_whitespace() {
        i += 1;
    }
    i
}

fn parse_one_declaration(prop: &str, val: &str) -> Option<Declaration> {
    let value = parse_css_value(val);
    Some(Declaration::new(String::from(prop).to_ascii_lowercase(), value))
}

fn token_to_string(token: &CssToken) -> String {
    match token {
        CssToken::Number(n) => alloc::format!("{}", n),
        CssToken::Dimension(n, u) => alloc::format!("{}{}", n, u),
        CssToken::Percentage(n) => alloc::format!("{}%", n),
        CssToken::String(s) => s.clone(),
        CssToken::Hash(s) => alloc::format!("#{}", s),
        _ => String::new(),
    }
}
