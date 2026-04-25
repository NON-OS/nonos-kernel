pub mod cascade;
pub mod color;
pub mod color_named;
pub mod color_rgb;
pub mod error;
pub mod parser;
pub mod properties;
pub mod selector;
pub mod tokenizer;
pub mod types;

#[cfg(test)]
mod tests_cascade;
#[cfg(test)]
mod tests_color;
#[cfg(test)]
mod tests_parser;
#[cfg(test)]
mod tests_selector;

pub use cascade::{default_style, resolve_style, ComputedStyle, TextAlign};
pub use color::parse_color;
pub use error::CssError;
pub use parser::{parse_inline_style, parse_stylesheet, Declaration, Rule, Stylesheet};
pub use properties::{Display, Position};
pub use selector::{Selector, Specificity};
pub use tokenizer::tokenize;
pub use types::{CssColor, CssValue, Unit};
