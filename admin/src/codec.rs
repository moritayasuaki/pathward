//! Bounded records, duplicate rejection and Python-compatible ASCII canonical JSON.
use crate::{Result, require};
use ring::digest::{Context, SHA256};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};
use std::fmt;

pub const LIMIT: usize = 1 << 20;
pub fn hash(bytes: &[u8]) -> String {
    let mut h = Context::new(&SHA256);
    h.update(bytes);
    h.finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unique bounded JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(x)) = a.next_element()? {
                    out.push(x);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Map::new();
                while let Some((k, Unique(v))) = a.next_entry::<String, Unique>()? {
                    if out.insert(k, v).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Value> {
    require(bytes.len() <= LIMIT, "record too large")?;
    Ok(serde_json::from_slice::<Unique>(bytes)?.0)
}

pub fn canonical(v: &Value) -> Vec<u8> {
    // serde_json's default map is ordered. Python's legacy envelope hashes ASCII
    // with ensure_ascii=True, including surrogate pairs for non-BMP characters.
    let json = serde_json::to_string(v).expect("Value serializes");
    let mut ascii = String::new();
    for ch in json.chars() {
        if ch.is_ascii() {
            ascii.push(ch);
        } else {
            for word in ch.encode_utf16(&mut [0; 2]) {
                ascii.push_str(&format!("\\u{word:04x}"));
            }
        }
    }
    ascii.into_bytes()
}
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = canonical(&json!({"format":1,"payload":v,"sha256":hash(&canonical(v))}));
    out.push(b'\n');
    out
}
pub fn decode(bytes: &[u8]) -> Result<Value> {
    // Hash the exact payload bytes written by either implementation. This also
    // preserves legacy floating-point metadata without reformatting numbers.
    let start = b"{\"format\":1,\"payload\":";
    let marker = b",\"sha256\":\"";
    require(
        bytes.len() <= LIMIT && bytes.starts_with(start) && bytes.ends_with(b"\"}\n"),
        "invalid record envelope",
    )?;
    let end = bytes
        .len()
        .checked_sub(marker.len() + 64 + 3)
        .ok_or("short envelope")?;
    require(
        end >= start.len() && &bytes[end..end + marker.len()] == marker,
        "invalid checksum field",
    )?;
    let digest = std::str::from_utf8(&bytes[end + marker.len()..bytes.len() - 3])?;
    let raw = &bytes[start.len()..end];
    require(hash(raw) == digest, "record checksum mismatch")?;
    let payload = parse(raw)?;
    require(payload.is_object(), "payload must be object")?;
    Ok(payload)
}
pub fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing string: {key}").into())
}
pub fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
