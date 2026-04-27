extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

#[derive(Clone, Debug)]
pub struct ProtoObject {
    pub properties: Rc<RefCell<BTreeMap<String, super::super::runtime::JsValue>>>,
    pub prototype: Option<Rc<ProtoObject>>,
}

pub struct ProtoChain;

impl ProtoChain {
    pub fn get_property(obj: &ProtoObject, name: &str) -> Option<super::super::runtime::JsValue> {
        if let Some(val) = obj.properties.borrow().get(name) {
            return Some(val.clone());
        }
        if let Some(ref proto) = obj.prototype {
            return Self::get_property(proto, name);
        }
        None
    }

    pub fn set_own_property(obj: &ProtoObject, name: &str, value: super::super::runtime::JsValue) {
        obj.properties.borrow_mut().insert(String::from(name), value);
    }

    pub fn has_own_property(obj: &ProtoObject, name: &str) -> bool {
        obj.properties.borrow().contains_key(name)
    }

    pub fn has_property(obj: &ProtoObject, name: &str) -> bool {
        Self::get_property(obj, name).is_some()
    }

    pub fn chain_depth(obj: &ProtoObject) -> u32 {
        let mut depth = 0u32;
        let mut current = obj.prototype.clone();
        while let Some(proto) = current {
            depth += 1;
            if depth > 16 {
                break;
            }
            current = proto.prototype.clone();
        }
        depth
    }
}

impl ProtoObject {
    pub fn new() -> Self {
        Self { properties: Rc::new(RefCell::new(BTreeMap::new())), prototype: None }
    }

    pub fn with_proto(proto: Rc<ProtoObject>) -> Self {
        Self { properties: Rc::new(RefCell::new(BTreeMap::new())), prototype: Some(proto) }
    }
}
