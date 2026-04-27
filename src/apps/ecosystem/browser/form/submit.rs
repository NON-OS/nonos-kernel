// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use super::encode::{build_form_urlencoded, resolve_url};
use crate::apps::ecosystem::browser::engine::Form;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Collect name=value pairs from a Form, filtering out submit/button inputs.
pub fn collect_form_data(form: &Form) -> Vec<(String, String)> {
    form.inputs
        .iter()
        .filter(|i| !i.name.is_empty())
        .filter(|i| i.input_type != "submit" && i.input_type != "button" && i.input_type != "reset")
        .map(|i| (i.name.clone(), i.value.clone()))
        .collect()
}

/// Result of form submission preparation — the caller handles navigation.
pub enum FormAction {
    /// Navigate to URL with query string appended (GET form)
    Get { url: String },
    /// Navigate to URL with POST body (POST form)
    Post { url: String, body: Vec<u8>, content_type: &'static str },
}

/// Prepare a form submission: resolve the action URL, collect data,
/// and return the navigation action to perform.
pub fn prepare_form_submission(form: &Form, base_url: &str) -> FormAction {
    let data = collect_form_data(form);
    let encoded = build_form_urlencoded(&data);
    let action_url = resolve_url(&form.action, base_url);

    match form.method.to_ascii_uppercase().as_str() {
        "GET" => {
            let url = if action_url.contains('?') {
                format!("{}&{}", action_url, encoded)
            } else {
                format!("{}?{}", action_url, encoded)
            };
            FormAction::Get { url }
        }
        _ => {
            // POST is the default for non-GET methods
            FormAction::Post {
                url: action_url,
                body: encoded.into_bytes(),
                content_type: "application/x-www-form-urlencoded",
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::ecosystem::browser::engine::FormInput;

    fn make_form(method: &str, action: &str, inputs: Vec<FormInput>) -> Form {
        Form { action: String::from(action), method: String::from(method), inputs }
    }

    fn make_input(name: &str, input_type: &str, value: &str) -> FormInput {
        FormInput {
            name: String::from(name),
            input_type: String::from(input_type),
            value: String::from(value),
            placeholder: None,
        }
    }

    #[test]
    fn test_collect_form_data_filters_submit() {
        let form = make_form(
            "POST",
            "/login",
            vec![
                make_input("user", "text", "admin"),
                make_input("pass", "password", "secret"),
                make_input("go", "submit", "Login"),
                make_input("", "hidden", "ignored"),
                make_input("reset", "reset", "Clear"),
                make_input("btn", "button", "Click"),
            ],
        );
        let data = collect_form_data(&form);
        assert_eq!(data.len(), 2);
        assert_eq!(data[0], (String::from("user"), String::from("admin")));
        assert_eq!(data[1], (String::from("pass"), String::from("secret")));
    }

    #[test]
    fn test_prepare_get_form() {
        let form = make_form("GET", "/search", vec![make_input("q", "text", "rust kernel")]);
        match prepare_form_submission(&form, "https://example.com/page") {
            FormAction::Get { url } => {
                assert_eq!(url, "https://example.com/search?q=rust+kernel");
            }
            _ => panic!("Expected GET form action"),
        }
    }

    #[test]
    fn test_prepare_post_form() {
        let form = make_form(
            "POST",
            "/login",
            vec![make_input("user", "text", "admin"), make_input("pass", "password", "s3cr&t")],
        );
        match prepare_form_submission(&form, "https://example.com/") {
            FormAction::Post { url, body, content_type } => {
                assert_eq!(url, "https://example.com/login");
                assert_eq!(core::str::from_utf8(&body).unwrap(), "user=admin&pass=s3cr%26t");
                assert_eq!(content_type, "application/x-www-form-urlencoded");
            }
            _ => panic!("Expected POST form action"),
        }
    }

    #[test]
    fn test_prepare_default_method_is_post() {
        let form = make_form("", "/action", vec![make_input("field", "text", "value")]);
        match prepare_form_submission(&form, "https://example.com/") {
            FormAction::Post { .. } => {}
            _ => panic!("Expected POST for empty method"),
        }
    }

    #[test]
    fn test_prepare_get_existing_query() {
        let form = make_form("GET", "/search?lang=en", vec![make_input("q", "text", "test")]);
        match prepare_form_submission(&form, "https://example.com/") {
            FormAction::Get { url } => {
                assert_eq!(url, "https://example.com/search?lang=en&q=test");
            }
            _ => panic!("Expected GET form action"),
        }
    }
}
