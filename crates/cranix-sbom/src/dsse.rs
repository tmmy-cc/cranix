//! Dead Simple Signing Envelopes (DSSE v1) signed with the ed25519 keys of
//! `secret-key-files`. A signature's `keyid` is the key name, and `sig` is
//! the base64 signature over the pre-authentication encoding of the
//! payload type and payload.

use cranix_core::hash::{base64_decode, base64_encode};
use cranix_core::signing::{PublicKey, SecretKey};
use serde_json::{json, Value};

/// The payload type of an in-toto statement.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// `DSSEv1 <len(type)> <type> <len(body)> <body>`.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// An envelope holding `payload` with one signature per key.
pub fn sign(payload_type: &str, payload: &[u8], keys: &[SecretKey]) -> Value {
    let msg = pae(payload_type, payload);
    let signatures: Vec<Value> = keys
        .iter()
        .map(|k| {
            let sig = k.sign(&msg);
            let (_, b64) = sig.split_once(':').unwrap();
            json!({ "keyid": k.name, "sig": b64 })
        })
        .collect();
    json!({ "payload": base64_encode(payload), "payloadType": payload_type, "signatures": signatures })
}

/// A verified envelope: its payload type and payload, and the names of the
/// trusted keys whose signatures verify.
#[derive(Debug)]
pub struct Verified {
    pub payload_type: String,
    pub payload: Vec<u8>,
    pub keys: Vec<String>,
}

/// Checks that at least one signature of `envelope` is a valid signature
/// by one of `keys`.
pub fn verify(envelope: &Value, keys: &[PublicKey]) -> Result<Verified, String> {
    let field = |k: &str| envelope.get(k).and_then(Value::as_str).ok_or_else(|| format!("the envelope has no '{k}'"));
    let payload_type = field("payloadType")?.to_string();
    let payload = base64_decode(field("payload")?).ok_or("the envelope payload is not valid base64")?;
    let sigs = envelope.get("signatures").and_then(Value::as_array).ok_or("the envelope has no 'signatures'")?;
    let msg = pae(&payload_type, &payload);
    let mut good = Vec::new();
    for s in sigs {
        let (Some(id), Some(sig)) = (s.get("keyid").and_then(Value::as_str), s.get("sig").and_then(Value::as_str)) else {
            continue;
        };
        let text = format!("{id}:{sig}");
        if keys.iter().any(|k| k.verify(&msg, &text)) && !good.iter().any(|g| g == id) {
            good.push(id.to_string());
        }
    }
    if good.is_empty() {
        let names: Vec<&str> = sigs.iter().filter_map(|s| s.get("keyid").and_then(Value::as_str)).collect();
        return Err(if names.is_empty() {
            "the envelope has no signatures".into()
        } else {
            format!("no valid signature by a trusted key (signed by: {})", names.join(", "))
        });
    }
    Ok(Verified { payload_type, payload, keys: good })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_specification() {
        // The example from the DSSE protocol description.
        assert_eq!(pae("http://example.com/HelloWorld", b"hello world"), b"DSSEv1 29 http://example.com/HelloWorld 11 hello world");
    }

    #[test]
    fn round_trip_and_tampering() {
        let k = SecretKey::from_seed("test-1", &[3; 32]);
        let other = SecretKey::from_seed("test-1", &[4; 32]);
        let env = sign(IN_TOTO_PAYLOAD_TYPE, b"{\"a\":1}", std::slice::from_ref(&k));
        let v = verify(&env, &[k.to_public()]).unwrap();
        assert_eq!(v.payload, b"{\"a\":1}");
        assert_eq!(v.keys, ["test-1"]);
        assert!(verify(&env, &[other.to_public()]).unwrap_err().contains("signed by: test-1"));

        let mut bad = env.clone();
        bad["payload"] = json!(base64_encode(b"{\"a\":2}"));
        assert!(verify(&bad, &[k.to_public()]).is_err());
        let mut bad = env.clone();
        bad["payloadType"] = json!("text/plain");
        assert!(verify(&bad, &[k.to_public()]).is_err());
    }
}
