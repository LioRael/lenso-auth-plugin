//! Source-selected private event binding for the existing Auth owner store.
use crate::EventStorageBinding;
use lenso::RuntimeFailure;
#[cfg(not(target_arch = "wasm32"))]
pub fn state(_: &serde_json::Value) -> Result<EventStorageBinding, RuntimeFailure> {
    Err(RuntimeFailure::InvalidResolvedPlan {
        detail: "Auth D1 facility requires Workers; Native PostgreSQL uses no state facility"
            .into(),
    })
}
#[cfg(all(target_arch = "wasm32", feature = "workers"))]
pub fn state(value: &wasm_bindgen::JsValue) -> Result<EventStorageBinding, RuntimeFailure> {
    use wasm_bindgen::JsCast;
    let invalid = || RuntimeFailure::InvalidResolvedPlan {
        detail: "invalid Auth event-owned D1 facility".into(),
    };
    let name = js_sys::Reflect::get(value, &wasm_bindgen::JsValue::from_str("name"))
        .map_err(|_| invalid())?
        .as_string()
        .ok_or_else(invalid)?;
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(invalid());
    }
    let batch = js_sys::Reflect::get(value, &wasm_bindgen::JsValue::from_str("batch"))
        .map_err(|_| invalid())?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| invalid())?;
    Ok(crate::workers::D1Binding::new(name, batch))
}
