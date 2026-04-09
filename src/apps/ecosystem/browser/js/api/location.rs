extern crate alloc;
use alloc::string::String;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_location(url: &str) -> JsValue {
    let mut obj = BTreeMap::new();
    let parts = parse_location(url);
    obj.insert(String::from("href"), JsValue::String(String::from(url)));
    obj.insert(String::from("origin"), JsValue::String(parts.0));
    obj.insert(String::from("protocol"), JsValue::String(parts.1));
    obj.insert(String::from("host"), JsValue::String(parts.2));
    obj.insert(String::from("hostname"), JsValue::String(parts.3));
    obj.insert(String::from("port"), JsValue::String(parts.4));
    obj.insert(String::from("pathname"), JsValue::String(parts.5));
    obj.insert(String::from("search"), JsValue::String(parts.6));
    obj.insert(String::from("hash"), JsValue::String(parts.7));
    obj.insert(String::from("assign"), JsValue::NativeFunc(assign));
    obj.insert(String::from("replace"), JsValue::NativeFunc(replace));
    obj.insert(String::from("reload"), JsValue::NativeFunc(reload));
    obj.insert(String::from("toString"), JsValue::NativeFunc(to_string));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn parse_location(url: &str) -> (String, String, String, String, String, String, String, String) {
    let mut rest = url;
    let protocol = if let Some(i) = rest.find("://") { let p = alloc::format!("{}:", &rest[..i]); rest = &rest[i + 3..]; p } else { String::from("https:") };
    let hash = if let Some(i) = rest.find('#') { let h = String::from(&rest[i..]); rest = &rest[..i]; h } else { String::new() };
    let search = if let Some(i) = rest.find('?') { let s = String::from(&rest[i..]); rest = &rest[..i]; s } else { String::new() };
    let (host, pathname) = if let Some(i) = rest.find('/') { (String::from(&rest[..i]), String::from(&rest[i..])) } else { (String::from(rest), String::from("/")) };
    let (hostname, port) = if let Some(i) = host.find(':') { (String::from(&host[..i]), String::from(&host[i + 1..])) } else { (host.clone(), String::new()) };
    let origin = alloc::format!("{}//{}", protocol, host);
    (origin, protocol, host, hostname, port, pathname, search, hash)
}

fn assign(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn replace(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn reload(_args: &[JsValue]) -> JsValue { JsValue::Undefined }

fn to_string(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(ref o)) = args.first() {
        o.borrow().get("href").cloned().unwrap_or(JsValue::Undefined)
    } else { JsValue::Undefined }
}
