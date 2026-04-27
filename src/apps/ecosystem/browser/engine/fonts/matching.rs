use super::builtin;
use super::metrics::FontMetrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontFamily {
    Monospace,
    SansSerif,
    Serif,
}

pub fn match_font_family(css_family: &str) -> FontMetrics {
    let lower = css_family.to_ascii_lowercase();
    let family = if lower.contains("monospace") || lower.contains("courier") {
        FontFamily::Monospace
    } else if lower.contains("serif") && !lower.contains("sans") {
        FontFamily::Serif
    } else {
        FontFamily::SansSerif
    };
    builtin::builtin_metrics(family)
}
