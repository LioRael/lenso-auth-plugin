//! Private Auth persistence transport. This is not a Lenso Capability.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, rc::Rc};
use wasm_bindgen::JsValue;

/// An event-owned bridge to exactly one named primary D1 binding.
#[derive(Clone)]
pub struct D1Binding {
    name: Rc<str>,
    batch: js_sys::Function,
}
impl fmt::Debug for D1Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("D1Binding")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
impl D1Binding {
    /// `batch` accepts JSON statements and returns a Promise of JSON results.
    /// Use Auth-owned `createD1StorageScope().bind(database)` and wire its finalizers.
    pub fn new(name: impl Into<Rc<str>>, batch: js_sys::Function) -> Self {
        Self {
            name: name.into(),
            batch,
        }
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) async fn run(&self, statements: Vec<Statement>) -> Result<Vec<BatchResult>, ()> {
        let input = serde_json::to_string(&statements).map_err(|_| ())?;
        let promise = self
            .batch
            .call1(&JsValue::NULL, &JsValue::from_str(&input))
            .map_err(|_| ())?;
        let value = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&promise))
            .await
            .map_err(|_| ())?;
        let results: Vec<BatchResult> =
            serde_json::from_str(&value.as_string().ok_or(())?).map_err(|_| ())?;
        if results.len() != statements.len() || results.iter().any(|r| !r.success) {
            return Err(());
        }
        Ok(results)
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct Statement {
    pub sql: String,
    pub params: Vec<Value>,
}
pub(crate) fn statement(sql: impl Into<String>, params: Vec<Value>) -> Statement {
    Statement {
        sql: sql.into(),
        params,
    }
}
#[derive(Debug, Deserialize)]
pub(crate) struct BatchResult {
    pub success: bool,
    #[serde(default)]
    pub results: Vec<Value>,
    pub meta: Meta,
}
#[derive(Debug, Deserialize)]
pub(crate) struct Meta {
    pub changes: u64,
}
pub(crate) fn field<T: serde::de::DeserializeOwned>(row: &Value, name: &str) -> Result<T, ()> {
    serde_json::from_value(row.get(name).ok_or(())?.clone()).map_err(|_| ())
}
pub(crate) fn timestamp(value: time::OffsetDateTime) -> Value {
    let v = value.to_offset(time::UtcOffset::UTC);
    serde_json::json!(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        v.year(),
        u8::from(v.month()),
        v.day(),
        v.hour(),
        v.minute(),
        v.second(),
        v.nanosecond()
    ))
}
pub(crate) fn decode_time(row: &Value, name: &str) -> Result<time::OffsetDateTime, ()> {
    let text: String = field(row, name)?;
    time::OffsetDateTime::parse(&text, &time::format_description::well_known::Rfc3339)
        .map_err(|_| ())
}
