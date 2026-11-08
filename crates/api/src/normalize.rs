use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::Result;

/// Lowercases the first character of every object key, recursively, so PascalCase
/// (`KdfIterations`), camelCase and snake_case (`access_token`) responses deserialize into the
/// same camelCase models. When both spellings of a key are present, the one that was already
/// lowercase wins, independent of map iteration order.
pub(crate) fn normalize_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.keys().any(|key| starts_uppercase(key)) {
                let old = std::mem::take(map);
                let mut renamed = Vec::new();
                for (key, mut child) in old {
                    normalize_keys(&mut child);
                    if starts_uppercase(&key) {
                        renamed.push((lower_first(key), child));
                    } else {
                        map.insert(key, child);
                    }
                }
                for (key, child) in renamed {
                    map.entry(key).or_insert(child);
                }
            } else {
                map.values_mut().for_each(normalize_keys);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_keys),
        _ => {}
    }
}

fn starts_uppercase(key: &str) -> bool {
    key.chars().next().is_some_and(char::is_uppercase)
}

fn lower_first(key: String) -> String {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_uppercase() => first.to_lowercase().chain(chars).collect(),
        _ => key,
    }
}

/// Parses a response body, normalizes its keys and deserializes it. The raw bytes are dropped
/// before `from_value` runs so a large sync is not held in three representations at once.
pub(crate) fn parse_normalized<T: DeserializeOwned>(body: Vec<u8>) -> Result<T> {
    let mut value: Value = serde_json::from_slice(&body)?;
    drop(body);
    normalize_keys(&mut value);
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn normalized(mut value: Value) -> Value {
        normalize_keys(&mut value);
        value
    }

    #[test]
    fn pascal_case_keys_become_camel_case() {
        let input = json!({"Key": "k", "KdfIterations": 600_000, "PrivateKey": null});
        assert_eq!(
            normalized(input),
            json!({"key": "k", "kdfIterations": 600_000, "privateKey": null})
        );
    }

    #[test]
    fn snake_and_camel_case_keys_are_unchanged() {
        let input = json!({"access_token": "t", "expires_in": 7200, "twoFactorToken": "x"});
        assert_eq!(normalized(input.clone()), input);
    }

    #[test]
    fn nested_objects_and_arrays_are_normalized() {
        let input = json!({
            "UserDecryptionOptions": {"MasterPasswordUnlock": {"Kdf": {"Iterations": 3}}},
            "Items": [{"Id": "a"}, [{"Name": "b"}]]
        });
        assert_eq!(
            normalized(input),
            json!({
                "userDecryptionOptions": {"masterPasswordUnlock": {"kdf": {"iterations": 3}}},
                "items": [{"id": "a"}, [{"name": "b"}]]
            })
        );
    }

    #[test]
    fn values_are_never_touched() {
        let input = json!({"Name": "Capitalized Value", "list": ["Keep", "Me"]});
        assert_eq!(
            normalized(input),
            json!({"name": "Capitalized Value", "list": ["Keep", "Me"]})
        );
    }

    #[test]
    fn digit_and_empty_keys_are_unchanged() {
        let input = json!({"0": null, "": 1, "_status": 0});
        assert_eq!(normalized(input.clone()), input);
    }

    #[test]
    fn non_ascii_uppercase_first_character_is_lowercased() {
        assert_eq!(normalized(json!({"Édition": 1})), json!({"édition": 1}));
    }

    #[test]
    fn mixed_object_normalizes_only_uppercase_keys() {
        let input = json!({"Key": 1, "kdf": 2, "Nested": {"Deep": {"Er": true}}});
        assert_eq!(
            normalized(input),
            json!({"key": 1, "kdf": 2, "nested": {"deep": {"er": true}}})
        );
    }

    #[test]
    fn already_lowercase_spelling_wins_over_converted_duplicate() {
        let input: Value = serde_json::from_str(r#"{"Key": "pascal", "key": "camel"}"#).unwrap();
        assert_eq!(normalized(input), json!({"key": "camel"}));
    }

    #[test]
    fn parse_normalized_deserializes_pascal_case_into_camel_case_model() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        #[serde(rename_all = "camelCase")]
        struct Model {
            kdf_iterations: u32,
            #[serde(rename = "access_token")]
            token: String,
        }
        let model: Model =
            parse_normalized(br#"{"KdfIterations": 5, "access_token": "t"}"#.to_vec()).unwrap();
        assert_eq!(
            model,
            Model {
                kdf_iterations: 5,
                token: "t".into()
            }
        );
    }

    #[test]
    fn parse_normalized_reports_invalid_json_as_decode_error() {
        let result: Result<Value> = parse_normalized(b"<html>".to_vec());
        assert!(matches!(result, Err(crate::Error::Decode(_))));
    }
}
