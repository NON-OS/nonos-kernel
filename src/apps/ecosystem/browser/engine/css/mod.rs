pub mod types;
pub mod error;
pub mod color;
pub mod color_rgb;
pub mod color_named;
pub mod tokenizer;
pub mod parser;
pub mod selector;
pub mod cascade;
pub mod properties;

#[cfg(test)]
mod tests_color;
#[cfg(test)]
mod tests_parser;
#[cfg(test)]
mod tests_selector;
#[cfg(test)]
mod tests_cascade;

pub use types::{CssValue, CssColor, Unit};
pub use error::CssError;
pub use color::parse_color;
pub use tokenizer::tokenize;
pub use selector::{Selector, Specificity};
pub use parser::{Stylesheet, Rule, Declaration, parse_stylesheet, parse_inline_style};
pub use cascade::{ComputedStyle, TextAlign, default_style, resolve_style};
pub use properties::{Display, Position};
