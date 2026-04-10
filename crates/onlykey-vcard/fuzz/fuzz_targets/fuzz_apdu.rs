#![no_main]
use libfuzzer_sys::fuzz_target;
use onlykey_vcard::apdu::Apdu;

fuzz_target!(|data: &[u8]| {
    let _ = Apdu::parse(data);
});
