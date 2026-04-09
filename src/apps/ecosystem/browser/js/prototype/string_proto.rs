extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use super::chain::ProtoObject;
use super::super::runtime::JsValue;

pub fn populate(proto: &ProtoObject) {
    let p = &proto.properties;
    p.borrow_mut().insert(String::from("toUpperCase"), JsValue::NativeFunc(to_upper_case));
    p.borrow_mut().insert(String::from("toLowerCase"), JsValue::NativeFunc(to_lower_case));
    p.borrow_mut().insert(String::from("charAt"), JsValue::NativeFunc(char_at));
    p.borrow_mut().insert(String::from("indexOf"), JsValue::NativeFunc(index_of));
    p.borrow_mut().insert(String::from("includes"), JsValue::NativeFunc(includes));
    p.borrow_mut().insert(String::from("trim"), JsValue::NativeFunc(trim));
    p.borrow_mut().insert(String::from("trimStart"), JsValue::NativeFunc(trim_start));
    p.borrow_mut().insert(String::from("trimEnd"), JsValue::NativeFunc(trim_end));
    p.borrow_mut().insert(String::from("slice"), JsValue::NativeFunc(slice));
    p.borrow_mut().insert(String::from("split"), JsValue::NativeFunc(split));
    p.borrow_mut().insert(String::from("startsWith"), JsValue::NativeFunc(starts_with));
    p.borrow_mut().insert(String::from("endsWith"), JsValue::NativeFunc(ends_with));
    p.borrow_mut().insert(String::from("repeat"), JsValue::NativeFunc(repeat));
    p.borrow_mut().insert(String::from("substring"), JsValue::NativeFunc(substring));
    p.borrow_mut().insert(String::from("replace"), JsValue::NativeFunc(replace));
    p.borrow_mut().insert(String::from("concat"), JsValue::NativeFunc(concat_str));
}

fn s(a: &[JsValue]) -> String { a.first().map(|v| v.to_string()).unwrap_or_default() }
fn a1(a: &[JsValue]) -> String { a.get(1).map(|v| v.to_string()).unwrap_or_default() }

fn to_upper_case(a: &[JsValue]) -> JsValue { JsValue::String(s(a).chars().map(|c| c.to_ascii_uppercase()).collect()) }
fn to_lower_case(a: &[JsValue]) -> JsValue { JsValue::String(s(a).chars().map(|c| c.to_ascii_lowercase()).collect()) }
fn char_at(a: &[JsValue]) -> JsValue { let i = a.get(1).map(|v| v.to_number() as usize).unwrap_or(0); s(a).chars().nth(i).map(|c| JsValue::String(alloc::format!("{}", c))).unwrap_or(JsValue::String(String::new())) }
fn index_of(a: &[JsValue]) -> JsValue { JsValue::Number(s(a).find(&*a1(a)).map(|i| i as f64).unwrap_or(-1.0)) }
fn includes(a: &[JsValue]) -> JsValue { JsValue::Bool(s(a).contains(&*a1(a))) }
fn trim(a: &[JsValue]) -> JsValue { JsValue::String(String::from(s(a).trim())) }
fn trim_start(a: &[JsValue]) -> JsValue { JsValue::String(String::from(s(a).trim_start())) }
fn trim_end(a: &[JsValue]) -> JsValue { JsValue::String(String::from(s(a).trim_end())) }
fn starts_with(a: &[JsValue]) -> JsValue { JsValue::Bool(s(a).starts_with(&*a1(a))) }
fn ends_with(a: &[JsValue]) -> JsValue { JsValue::Bool(s(a).ends_with(&*a1(a))) }
fn concat_str(a: &[JsValue]) -> JsValue { let mut r = s(a); for v in &a[1..] { r.push_str(&v.to_string()); } JsValue::String(r) }
fn repeat(a: &[JsValue]) -> JsValue { JsValue::String(s(a).repeat(a.get(1).map(|v| v.to_number() as usize).unwrap_or(0))) }

fn replace(a: &[JsValue]) -> JsValue {
    let rep = a.get(2).map(|v| v.to_string()).unwrap_or_default();
    JsValue::String(s(a).replacen(&*a1(a), &rep, 1))
}

fn slice(a: &[JsValue]) -> JsValue {
    let st = s(a);
    let len = st.len() as i64;
    let mut start = a.get(1).map(|v| v.to_number() as i64).unwrap_or(0);
    let mut end = a.get(2).map(|v| if matches!(v, JsValue::Undefined) { len } else { v.to_number() as i64 }).unwrap_or(len);
    if start < 0 { start = (len + start).max(0); }
    if end < 0 { end = (len + end).max(0); }
    let (start, end) = ((start as usize).min(st.len()), (end as usize).min(st.len()));
    if start >= end { return JsValue::String(String::new()); }
    JsValue::String(String::from(&st[start..end]))
}

fn substring(a: &[JsValue]) -> JsValue {
    let st = s(a);
    let len = st.len();
    let mut start = a.get(1).map(|v| v.to_number() as usize).unwrap_or(0).min(len);
    let mut end = a.get(2).map(|v| if matches!(v, JsValue::Undefined) { len } else { (v.to_number() as usize).min(len) }).unwrap_or(len);
    if start > end { core::mem::swap(&mut start, &mut end); }
    JsValue::String(String::from(&st[start..end]))
}

fn split(a: &[JsValue]) -> JsValue {
    let st = s(a);
    let sep = a1(a);
    let parts: Vec<JsValue> = if sep.is_empty() {
        st.chars().map(|c| JsValue::String(alloc::format!("{}", c))).collect()
    } else {
        st.split(&*sep).map(|p| JsValue::String(String::from(p))).collect()
    };
    JsValue::Array(Rc::new(RefCell::new(parts)))
}
