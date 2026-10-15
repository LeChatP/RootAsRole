#![no_main]

use libfuzzer_sys::fuzz_target;
use rootasrole_core::database::structs::SPolicy;
use rootasrole_core::database::versionning::Versioning;
use rootasrole_core::file::RootSettings;
use serde::{Serialize, de::DeserializeOwned};

/// A parsed file must be written back and parsed again to the same content.
fn assert_round_trip<T: Serialize + DeserializeOwned>(value: &T) {
    let first = serde_json::to_value(value).expect("a parsed policy must serialize");
    let again: T =
        serde_json::from_value(first.clone()).expect("a serialized policy must parse back");
    assert_eq!(serde_json::to_value(&again).unwrap(), first);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(settings) = serde_json::from_slice::<Versioning<RootSettings>>(data) {
        assert_round_trip(&settings);
    }
    if let Ok(policy) = serde_json::from_slice::<Versioning<SPolicy>>(data) {
        assert_round_trip(&policy);
    }
    if let Ok(policy) = cbor4ii::serde::from_slice::<Versioning<SPolicy>>(data) {
        assert_round_trip(&policy);
    }
});
