extern crate alloc;
use super::engine::JsRuntime;
use super::value::{JsArray, JsValue};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

impl JsRuntime {
    pub(super) fn array_callback(
        &mut self,
        arr: &JsArray,
        method: &str,
        args: &[JsValue],
    ) -> Option<JsValue> {
        match method {
            "map" => Some(self.array_map(arr, args)),
            "filter" => Some(self.array_filter(arr, args)),
            "forEach" => Some(self.array_for_each(arr, args)),
            "find" => Some(self.array_find(arr, args)),
            "findIndex" => Some(self.array_find_index(arr, args)),
            "some" => Some(self.array_some(arr, args)),
            "every" => Some(self.array_every(arr, args)),
            "reduce" => Some(self.array_reduce(arr, args)),
            _ => None,
        }
    }

    fn array_map(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        let mut result = Vec::with_capacity(items.len());
        for (i, v) in items.iter().enumerate() {
            result.push(self.invoke_value(&cb, &[v.clone(), JsValue::Number(i as f64)]));
        }
        JsValue::Array(Rc::new(RefCell::new(result)))
    }

    fn array_filter(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        let mut result = Vec::new();
        for (i, v) in items.iter().enumerate() {
            if self.invoke_value(&cb, &[v.clone(), JsValue::Number(i as f64)]).to_bool() {
                result.push(v.clone());
            }
        }
        JsValue::Array(Rc::new(RefCell::new(result)))
    }

    fn array_for_each(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        for (i, v) in items.iter().enumerate() {
            self.invoke_value(&cb, &[v.clone(), JsValue::Number(i as f64)]);
        }
        JsValue::Undefined
    }

    fn array_find(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        for (i, v) in items.iter().enumerate() {
            if self.invoke_value(&cb, &[v.clone(), JsValue::Number(i as f64)]).to_bool() {
                return v.clone();
            }
        }
        JsValue::Undefined
    }

    fn array_find_index(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        for (i, v) in items.iter().enumerate() {
            if self.invoke_value(&cb, &[v.clone(), JsValue::Number(i as f64)]).to_bool() {
                return JsValue::Number(i as f64);
            }
        }
        JsValue::Number(-1.0)
    }

    fn array_some(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        for (i, v) in items.iter().enumerate() {
            if self.invoke_value(&cb, &[v.clone(), JsValue::Number(i as f64)]).to_bool() {
                return JsValue::Bool(true);
            }
        }
        JsValue::Bool(false)
    }

    fn array_every(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        for (i, v) in items.iter().enumerate() {
            if !self.invoke_value(&cb, &[v.clone(), JsValue::Number(i as f64)]).to_bool() {
                return JsValue::Bool(false);
            }
        }
        JsValue::Bool(true)
    }

    fn array_reduce(&mut self, arr: &JsArray, args: &[JsValue]) -> JsValue {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let items = arr.borrow().clone();
        let mut acc = args
            .get(1)
            .cloned()
            .unwrap_or_else(|| items.first().cloned().unwrap_or(JsValue::Undefined));
        let start = if args.len() > 1 { 0 } else { 1 };
        for (i, v) in items.iter().enumerate().skip(start) {
            acc = self.invoke_value(&cb, &[acc, v.clone(), JsValue::Number(i as f64)]);
        }
        acc
    }
}
