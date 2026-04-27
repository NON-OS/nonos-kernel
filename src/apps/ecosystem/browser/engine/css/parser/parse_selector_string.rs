extern crate alloc;
use super::super::selector::Selector;
use super::super::tokenizer::tokenize;
use super::parse_selector::parse_selector;
use alloc::vec::Vec;

pub fn parse_selector_string(input: &str) -> Vec<Selector> {
    let tokens = tokenize(input);
    parse_selector(&tokens)
}
