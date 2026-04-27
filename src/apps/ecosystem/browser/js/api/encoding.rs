extern crate alloc;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

pub fn create_atob() -> JsValue {
    JsValue::NativeFunc(atob)
}
pub fn create_btoa() -> JsValue {
    JsValue::NativeFunc(btoa)
}

pub fn create_text_encoder() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("encoding"), JsValue::String(String::from("utf-8")));
    obj.insert(String::from("encode"), JsValue::NativeFunc(text_encode));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

pub fn create_text_decoder() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("encoding"), JsValue::String(String::from("utf-8")));
    obj.insert(String::from("decode"), JsValue::NativeFunc(text_decode));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn btoa(args: &[JsValue]) -> JsValue {
    let input = args.first().map(|v| v.to_string()).unwrap_or_default();
    JsValue::String(base64_encode(input.as_bytes()))
}

fn atob(args: &[JsValue]) -> JsValue {
    let input = args.first().map(|v| v.to_string()).unwrap_or_default();
    let bytes = base64_decode(&input);
    JsValue::String(String::from_utf8_lossy(&bytes).into_owned())
}

fn text_encode(args: &[JsValue]) -> JsValue {
    let s = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    let arr: Vec<JsValue> = s.as_bytes().iter().map(|&b| JsValue::Number(b as f64)).collect();
    JsValue::Array(Rc::new(RefCell::new(arr)))
}

fn text_decode(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Array(ref arr)) = args.get(1) {
        let bytes: Vec<u8> = arr.borrow().iter().map(|v| v.to_number() as u8).collect();
        JsValue::String(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        JsValue::String(String::new())
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_val(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=' && b != b'\n' && b != b'\r').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let (a, b) = (b64_val(chunk[0]) as u32, b64_val(chunk[1]) as u32);
        let c = if chunk.len() > 2 { b64_val(chunk[2]) as u32 } else { 0 };
        let d = if chunk.len() > 3 { b64_val(chunk[3]) as u32 } else { 0 };
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((triple >> 16) as u8);
        if chunk.len() > 2 {
            out.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(triple as u8);
        }
    }
    out
}
