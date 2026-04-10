//! BER-TLV encode/decode round-trip fuzz harness.
//!
//! Verifies the property: parse(encode(parse(input))) == parse(input).
//! The plain fuzz_ber_tlv target only checks that parse() doesn't panic;
//! this target additionally catches encoding bugs by re-encoding parsed
//! output and asserting the second parse is identical. Issue OnlyKey-p98.
#![no_main]
use libfuzzer_sys::fuzz_target;
use onlykey_vcard::apdu::{parse_tlv, tlv};

fuzz_target!(|data: &[u8]| {
    let parsed = parse_tlv(data);
    if parsed.is_empty() {
        return;
    }

    // Re-encode all parsed TLV objects into canonical form.
    let mut encoded: Vec<u8> = Vec::new();
    for (tag, value) in &parsed {
        encoded.extend_from_slice(&tlv(tag, value));
    }

    // Re-parse the canonical encoding.
    let reparsed = parse_tlv(&encoded);

    // Round-trip property: parse(encode(parse(x))) == parse(x).
    // A failure here means either tlv() encodes something parse_tlv() cannot
    // reproduce, or parse_tlv() behaves non-deterministically.
    assert_eq!(
        parsed, reparsed,
        "BER-TLV round-trip failure:\n  first parse:  {:?}\n  re-encoded:   {:?}\n  second parse: {:?}",
        parsed, encoded, reparsed
    );
});
