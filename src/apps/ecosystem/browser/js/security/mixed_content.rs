extern crate alloc;
use alloc::string::String;

pub fn block_mixed_content(page_url: &str, resource_url: &str) -> bool {
    let page_secure = page_url.starts_with("https://");
    let resource_insecure = resource_url.starts_with("http://");
    page_secure && resource_insecure
}

pub fn upgrade_insecure_request(page_url: &str, resource_url: &str) -> String {
    if block_mixed_content(page_url, resource_url) && resource_url.starts_with("http://") {
        let mut upgraded = String::from("https://");
        upgraded.push_str(&resource_url[7..]);
        upgraded
    } else {
        String::from(resource_url)
    }
}

pub fn should_block_nosniff(content_type_header: Option<&str>, expected: &str) -> bool {
    if let Some(ct) = content_type_header {
        let mime = ct.split(';').next().unwrap_or("").trim();
        if expected == "script" {
            return !is_javascript_mime(mime);
        }
        if expected == "style" {
            return mime != "text/css";
        }
    }
    false
}

fn is_javascript_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/javascript"
            | "text/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "text/ecmascript"
    )
}
