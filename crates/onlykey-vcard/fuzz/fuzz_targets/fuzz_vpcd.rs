#![no_main]
use libfuzzer_sys::fuzz_target;
use onlykey_vcard::vpcd::VpcdConnection;
use std::io::Write;
use std::net::{TcpListener, TcpStream};

fuzz_target!(|data: &[u8]| {
    // Build a vpcd-framed message: 2-byte big-endian length + payload.
    // We fuzz both the length field and payload together by treating the
    // first 2 bytes of `data` as the length header and the rest as payload.
    if data.len() < 2 {
        return;
    }

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return,
    };
    let addr = listener.local_addr().unwrap();

    let data_owned = data.to_vec();
    let writer = std::thread::spawn(move || {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            let _ = stream.write_all(&data_owned);
        }
    });

    if let Ok((stream, _)) = listener.accept() {
        let mut conn = VpcdConnection::new(stream);
        let _ = conn.read_message();
    }

    let _ = writer.join();
});
