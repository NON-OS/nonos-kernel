use super::super::types::AriaRole;

pub fn implicit_role(tag: &str) -> AriaRole {
    match tag {
        "a" => AriaRole::Link,
        "article" => AriaRole::Article,
        "aside" => AriaRole::Complementary,
        "button" => AriaRole::Button,
        "dialog" => AriaRole::Dialog,
        "figure" => AriaRole::Figure,
        "footer" => AriaRole::ContentInfo,
        "form" => AriaRole::Form,
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => AriaRole::Heading,
        "header" => AriaRole::Banner,
        "hr" => AriaRole::Separator,
        "img" => AriaRole::Img,
        "input" => AriaRole::TextBox,
        "li" => AriaRole::ListItem,
        "main" => AriaRole::Main,
        "nav" => AriaRole::Navigation,
        "ol" | "ul" => AriaRole::List,
        "option" => AriaRole::Option,
        "progress" => AriaRole::ProgressBar,
        "section" => AriaRole::Region,
        "select" => AriaRole::ListBox,
        "table" => AriaRole::Table,
        "td" | "th" => AriaRole::Cell,
        "textarea" => AriaRole::TextBox,
        "tr" => AriaRole::Row,
        _ => AriaRole::None,
    }
}

pub fn is_naturally_focusable(tag: &str) -> bool {
    matches!(tag, "a" | "button" | "input" | "select" | "textarea" | "summary" | "details")
}
