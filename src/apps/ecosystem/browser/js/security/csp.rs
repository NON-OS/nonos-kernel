extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct CspPolicy {
    pub directives: Vec<CspDirective>,
    pub report_only: bool,
}

#[derive(Debug, Clone)]
pub struct CspDirective {
    pub name: String,
    pub sources: Vec<String>,
}

impl CspPolicy {
    pub fn parse(header: &str, report_only: bool) -> Self {
        let directives = header
            .split(';')
            .filter_map(|d| {
                let parts: Vec<&str> = d.trim().splitn(2, ' ').collect();
                if parts.is_empty() || parts[0].is_empty() {
                    return None;
                }
                let name = String::from(parts[0]);
                let sources = if parts.len() > 1 {
                    parts[1].split_whitespace().map(String::from).collect()
                } else {
                    Vec::new()
                };
                Some(CspDirective { name, sources })
            })
            .collect();
        Self { directives, report_only }
    }

    fn get_directive(&self, name: &str) -> Option<&CspDirective> {
        self.directives
            .iter()
            .find(|d| d.name == name)
            .or_else(|| self.directives.iter().find(|d| d.name == "default-src"))
    }
}

pub fn csp_allows(
    policy: &CspPolicy,
    directive_name: &str,
    source: &str,
    page_origin: &str,
) -> bool {
    let directive = match policy.get_directive(directive_name) {
        Some(d) => d,
        None => return true,
    };
    if directive.sources.iter().any(|s| s == "'none'") {
        return false;
    }
    for src in &directive.sources {
        if matches_source(src, source, page_origin) {
            return true;
        }
    }
    false
}

fn matches_source(pattern: &str, source: &str, page_origin: &str) -> bool {
    match pattern {
        "*" => true,
        "'self'" => {
            let src_origin = super::origin::Origin::from_url(source);
            let page = super::origin::Origin::from_url(page_origin);
            src_origin.same_origin(&page)
        }
        "'unsafe-inline'" => true,
        "'unsafe-eval'" => true,
        _ => {
            if pattern.starts_with("'nonce-") {
                return false;
            }
            if pattern.starts_with("'sha") {
                return false;
            }
            source.starts_with(pattern)
        }
    }
}

pub fn csp_allows_inline_script(policy: &CspPolicy) -> bool {
    if let Some(d) = policy.get_directive("script-src") {
        d.sources.iter().any(|s| s == "'unsafe-inline'")
    } else {
        true
    }
}

pub fn csp_allows_eval(policy: &CspPolicy) -> bool {
    if let Some(d) = policy.get_directive("script-src") {
        d.sources.iter().any(|s| s == "'unsafe-eval'")
    } else {
        true
    }
}
