// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! What names a page: its title, or its site when the title is blank.

use crate::browser::shell::site_label::{site, title};

fn initial(s: &str) -> Option<char> {
    s.chars().find(|c| c.is_alphanumeric())
}

#[test]
fn a_title_wins_over_the_site() {
    assert_eq!(title("My Page", "https://example.com/a"), "My Page");
}

#[test]
fn a_blank_title_falls_back_to_the_host() {
    for t in ["", "   ", "\t\n"] {
        assert_eq!(title(t, "https://news.example.org/a/b?q=1"), "news.example.org");
    }
    assert_eq!(site("http://example.com/"), "example.com");
}

#[test]
fn an_address_without_a_host_names_itself() {
    assert_eq!(title("", "about:nonos"), "about:nonos");
    assert_eq!(site("about:blank"), "about:blank");
    assert_eq!(initial(&site("about:nonos")), Some('a'));
}

#[test]
fn nothing_at_all_stays_empty() {
    assert_eq!(title("", ""), "");
    assert_eq!(site(""), "");
}
