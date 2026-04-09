extern crate alloc;
use super::super::runtime::JsValue;

#[derive(Clone, Debug)]
pub enum ThisBinding {
    Global,
    Bound(JsValue),
    Arrow,
}

pub fn resolve_this(binding: &ThisBinding, enclosing_this: &JsValue) -> JsValue {
    match binding {
        ThisBinding::Global => JsValue::Undefined,
        ThisBinding::Bound(val) => val.clone(),
        ThisBinding::Arrow => enclosing_this.clone(),
    }
}

pub fn bind_method_this(receiver: JsValue) -> ThisBinding {
    ThisBinding::Bound(receiver)
}

pub fn bind_explicit_this(value: JsValue) -> ThisBinding {
    ThisBinding::Bound(value)
}

pub fn arrow_this() -> ThisBinding {
    ThisBinding::Arrow
}
