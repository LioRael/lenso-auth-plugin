//! Source-owned private storage attachment. No connection or migration runs here.
use lenso::RuntimeFailure;

/// Target-private attachment for one Auth Instance's original store.
#[derive(Clone, Debug)]
pub enum EventStorageBinding {
    #[cfg(feature = "postgres")]
    Postgres {
        storage_ref: String,
        database_url_secret: String,
    },
    #[cfg(feature = "workers")]
    D1 {
        storage_ref: Option<String>,
        binding: crate::workers::D1Binding,
    },
}

pub(crate) enum StorageSelection<'a> {
    Postgres(&'a str),
    #[cfg(feature = "workers")]
    D1(&'a crate::workers::D1Binding),
}

pub(crate) fn valid_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference.split('/').all(|part| part != "." && part != "..")
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

fn invalid() -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: "invalid or mismatched Auth storage attachment".into(),
    }
}

pub(crate) fn select<'a>(
    storage_ref: &str,
    database_url_secret: &'a str,
    d1_binding: &str,
    attachment: Option<&'a EventStorageBinding>,
) -> Result<StorageSelection<'a>, RuntimeFailure> {
    if !storage_ref.is_empty() {
        if !valid_reference(storage_ref)
            || !database_url_secret.is_empty()
            || !d1_binding.is_empty()
        {
            return Err(invalid());
        }
        match attachment.ok_or_else(invalid)? {
            #[cfg(not(any(feature = "postgres", feature = "workers")))]
            _ => Err(invalid()),
            #[cfg(feature = "postgres")]
            EventStorageBinding::Postgres {
                storage_ref: reference,
                database_url_secret,
            } => {
                if reference != storage_ref || !valid_reference(database_url_secret) {
                    return Err(invalid());
                }
                Ok(StorageSelection::Postgres(database_url_secret))
            }
            #[cfg(feature = "workers")]
            EventStorageBinding::D1 {
                storage_ref: reference,
                binding,
            } => {
                if reference.as_deref() != Some(storage_ref) {
                    return Err(invalid());
                }
                Ok(StorageSelection::D1(binding))
            }
        }
    } else if d1_binding.is_empty() {
        if attachment.is_some() || database_url_secret.is_empty() {
            return Err(invalid());
        }
        Ok(StorageSelection::Postgres(database_url_secret))
    } else {
        #[cfg(feature = "workers")]
        if let Some(EventStorageBinding::D1 {
            storage_ref: None,
            binding,
        }) = attachment
            && database_url_secret.is_empty()
            && binding.name() == d1_binding
        {
            return Ok(StorageSelection::D1(binding));
        }
        Err(invalid())
    }
}

/// Parses a logical reference and a Secrets reference; activation owns PG I/O.
#[cfg(not(target_arch = "wasm32"))]
pub fn state(value: &serde_json::Value) -> Result<EventStorageBinding, RuntimeFailure> {
    #[cfg(feature = "postgres")]
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Attachment {
            storage_ref: String,
            database_url_secret: String,
        }
        let attachment: Attachment =
            serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        if !valid_reference(&attachment.storage_ref)
            || !valid_reference(&attachment.database_url_secret)
        {
            return Err(invalid());
        }
        Ok(EventStorageBinding::Postgres {
            storage_ref: attachment.storage_ref,
            database_url_secret: attachment.database_url_secret,
        })
    }
    #[cfg(not(feature = "postgres"))]
    {
        let _ = value;
        Err(invalid())
    }
}

/// Receives the event-owned original D1 transport and optional logical reference.
#[cfg(all(target_arch = "wasm32", feature = "workers"))]
pub fn state(value: &wasm_bindgen::JsValue) -> Result<EventStorageBinding, RuntimeFailure> {
    use wasm_bindgen::JsCast;
    let get = |key: &str| {
        js_sys::Reflect::get(value, &wasm_bindgen::JsValue::from_str(key)).map_err(|_| invalid())
    };
    let name = get("name")?.as_string().ok_or_else(invalid)?;
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(invalid());
    }
    let reference = get("storage_ref")?;
    let storage_ref = if reference.is_undefined() {
        None
    } else {
        let reference = reference
            .as_string()
            .filter(|s| valid_reference(s))
            .ok_or_else(invalid)?;
        Some(reference)
    };
    let batch = get("batch")?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| invalid())?;
    Ok(EventStorageBinding::D1 {
        storage_ref,
        binding: crate::workers::D1Binding::new(name, batch),
    })
}

#[cfg(all(test, feature = "postgres", not(target_arch = "wasm32")))]
mod storage_reference_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_attachment_is_typed_and_per_instance_without_io() {
        let attachment = state(
            &json!({"storage_ref":"auth/account", "database_url_secret":"auth/account/database"}),
        )
        .unwrap();
        assert!(matches!(
            select("auth/account", "", "", Some(&attachment)).unwrap(),
            StorageSelection::Postgres("auth/account/database")
        ));
        assert!(select("auth/password", "", "", Some(&attachment)).is_err());
        assert!(select("auth/account", "", "", None).is_err());
        assert!(select("auth/account", "legacy", "", Some(&attachment)).is_err());
        assert!(select("auth/account", "", "LEGACY_D1", Some(&attachment)).is_err());
        assert!(select("", "legacy", "", Some(&attachment)).is_err());
    }

    #[test]
    fn native_parser_rejects_missing_invalid_and_extra_fields_without_io() {
        for payload in [
            json!({"storage_ref":"auth/account"}),
            json!({"storage_ref":"auth/account", "database_url_secret":""}),
            json!({"storage_ref":"../account", "database_url_secret":"database"}),
            json!({"storage_ref":"auth/account", "database_url_secret":"postgres://actual-location"}),
            json!({"storage_ref":"auth/account", "database_url_secret":"database", "migration":true}),
            json!({"storage_ref":"auth/account", "database_url_secret":"database", "d1_binding":"D1"}),
        ] {
            assert!(state(&payload).is_err());
        }
    }

    #[test]
    fn old_native_config_requires_no_attachment_and_never_falls_back() {
        assert!(matches!(
            select("", "legacy.database", "", None).unwrap(),
            StorageSelection::Postgres("legacy.database")
        ));
        assert!(select("", "", "D1", None).is_err());
        assert!(select("", "", "", None).is_err());
    }
}

#[cfg(all(test, feature = "workers", not(target_arch = "wasm32")))]
mod storage_reference_d1_tests {
    use super::*;
    use wasm_bindgen::JsCast;

    // An uncalled reserved JS handle permits typed reference-selection tests on Native.
    // These vectors exercise no bridge invocation and do not qualify D1 execution.
    fn attachment(reference: Option<&str>) -> EventStorageBinding {
        EventStorageBinding::D1 {
            storage_ref: reference.map(str::to_owned),
            binding: crate::workers::D1Binding::new(
                "AUTH_D1",
                wasm_bindgen::JsValue::NULL.unchecked_into(),
            ),
        }
    }

    #[test]
    fn d1_reference_selection_rejects_missing_mismatch_and_legacy_attachment() {
        let binding = attachment(Some("auth/account"));
        assert!(
            matches!(select("auth/account", "", "", Some(&binding)).unwrap(), StorageSelection::D1(value) if value.name() == "AUTH_D1")
        );
        assert!(select("auth/password", "", "", Some(&binding)).is_err());
        assert!(select("auth/account", "", "", None).is_err());
        assert!(select("auth/account", "", "AUTH_D1", Some(&binding)).is_err());
        assert!(select("", "", "AUTH_D1", Some(&binding)).is_err());
        assert!(select("auth/account", "", "", Some(&attachment(None))).is_err());
    }

    #[test]
    fn legacy_d1_selection_keeps_exact_physical_binding_check() {
        let binding = attachment(None);
        assert!(matches!(
            select("", "", "AUTH_D1", Some(&binding)).unwrap(),
            StorageSelection::D1(_)
        ));
        assert!(select("", "", "OTHER_D1", Some(&binding)).is_err());
        assert!(select("", "database", "AUTH_D1", Some(&binding)).is_err());
    }
}
