extern crate alloc;
use super::super::runtime::JsValue;
use super::chain::ProtoObject;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

pub fn populate(proto: &ProtoObject) {
    let p = &proto.properties;
    p.borrow_mut().insert(String::from("push"), JsValue::NativeFunc(push));
    p.borrow_mut().insert(String::from("pop"), JsValue::NativeFunc(pop));
    p.borrow_mut().insert(String::from("shift"), JsValue::NativeFunc(shift));
    p.borrow_mut().insert(String::from("unshift"), JsValue::NativeFunc(unshift));
    p.borrow_mut().insert(String::from("join"), JsValue::NativeFunc(join));
    p.borrow_mut().insert(String::from("indexOf"), JsValue::NativeFunc(index_of));
    p.borrow_mut().insert(String::from("includes"), JsValue::NativeFunc(includes));
    p.borrow_mut().insert(String::from("slice"), JsValue::NativeFunc(slice));
    p.borrow_mut().insert(String::from("concat"), JsValue::NativeFunc(concat));
    p.borrow_mut().insert(String::from("reverse"), JsValue::NativeFunc(reverse));
    p.borrow_mut().insert(String::from("flat"), JsValue::NativeFunc(flat));
    p.borrow_mut().insert(String::from("toString"), JsValue::NativeFunc(join));
}

fn arr(a: &[JsValue]) -> Option<Rc<RefCell<Vec<JsValue>>>> {
    if let Some(JsValue::Array(ref rc)) = a.first() {
        Some(rc.clone())
    } else {
        None
    }
}

fn push(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        for v in &a[1..] {
            rc.borrow_mut().push(v.clone());
        }
        JsValue::Number(rc.borrow().len() as f64)
    } else {
        JsValue::Undefined
    }
}

fn pop(a: &[JsValue]) -> JsValue {
    arr(a).and_then(|rc| rc.borrow_mut().pop()).unwrap_or(JsValue::Undefined)
}

fn shift(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        let mut v = rc.borrow_mut();
        if v.is_empty() {
            JsValue::Undefined
        } else {
            v.remove(0)
        }
    } else {
        JsValue::Undefined
    }
}

fn unshift(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        let items: Vec<JsValue> = a[1..].to_vec();
        let mut v = rc.borrow_mut();
        for (i, item) in items.into_iter().enumerate() {
            v.insert(i, item);
        }
        JsValue::Number(v.len() as f64)
    } else {
        JsValue::Undefined
    }
}

fn join(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        let sep = a.get(1).map(|v| v.to_string()).unwrap_or_else(|| String::from(","));
        let parts: Vec<String> = rc.borrow().iter().map(|v| v.to_string()).collect();
        JsValue::String(parts.join(&sep))
    } else {
        JsValue::Undefined
    }
}

fn index_of(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        let search = a.get(1).cloned().unwrap_or(JsValue::Undefined);
        for (i, v) in rc.borrow().iter().enumerate() {
            if v.to_string() == search.to_string() {
                return JsValue::Number(i as f64);
            }
        }
        JsValue::Number(-1.0)
    } else {
        JsValue::Number(-1.0)
    }
}

fn includes(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        let search = a.get(1).cloned().unwrap_or(JsValue::Undefined);
        JsValue::Bool(rc.borrow().iter().any(|v| v.to_string() == search.to_string()))
    } else {
        JsValue::Bool(false)
    }
}

fn slice(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        let v = rc.borrow();
        let len = v.len() as i64;
        let mut start = a.get(1).map(|v| v.to_number() as i64).unwrap_or(0);
        let mut end = a
            .get(2)
            .map(|v| if matches!(v, JsValue::Undefined) { len } else { v.to_number() as i64 })
            .unwrap_or(len);
        if start < 0 {
            start = (len + start).max(0);
        }
        if end < 0 {
            end = (len + end).max(0);
        }
        let (start, end) = ((start as usize).min(v.len()), (end as usize).min(v.len()));
        JsValue::Array(Rc::new(RefCell::new(v[start..end].to_vec())))
    } else {
        JsValue::Array(Rc::new(RefCell::new(Vec::new())))
    }
}

fn concat(a: &[JsValue]) -> JsValue {
    let mut result = Vec::new();
    if let Some(rc) = arr(a) {
        result.extend(rc.borrow().iter().cloned());
    }
    for v in &a[1..] {
        if let JsValue::Array(ref a2) = v {
            result.extend(a2.borrow().iter().cloned());
        } else {
            result.push(v.clone());
        }
    }
    JsValue::Array(Rc::new(RefCell::new(result)))
}

fn reverse(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        rc.borrow_mut().reverse();
        JsValue::Array(rc)
    } else {
        JsValue::Undefined
    }
}

fn flat(a: &[JsValue]) -> JsValue {
    if let Some(rc) = arr(a) {
        let mut result = Vec::new();
        for v in rc.borrow().iter() {
            if let JsValue::Array(ref inner) = v {
                result.extend(inner.borrow().iter().cloned());
            } else {
                result.push(v.clone());
            }
        }
        JsValue::Array(Rc::new(RefCell::new(result)))
    } else {
        JsValue::Undefined
    }
}
