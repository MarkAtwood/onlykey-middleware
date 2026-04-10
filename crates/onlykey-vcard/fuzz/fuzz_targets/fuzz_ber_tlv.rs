#![no_main]
use libfuzzer_sys::fuzz_target;
use onlykey_vcard::apdu::parse_tlv;

fuzz_target!(|data: &[u8]| {
    let _ = parse_tlv(data);
});
