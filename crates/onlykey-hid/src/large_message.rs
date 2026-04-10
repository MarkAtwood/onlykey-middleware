extern crate alloc;
use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::error::HidError;
use crate::packet::HidFrame;

/// Maximum payload that can be sent in a large-message sequence (firmware limit).
pub const MAX_PAYLOAD: usize = 768;

/// HID frame size (one USB full-speed packet).
const FRAME_SIZE: usize = 64;

/// Overhead bytes consumed by the frame header for each frame:
/// bytes [0..3]: `0xFF 0xFF 0xFF 0xFF` magic header (4 bytes)
/// byte  [4]:    command byte (1 byte)
/// byte  [5]:    slot byte (1 byte)
/// byte  [6]:    field byte: `0xFF` for non-last frames, payload length for last (1 byte)
/// Total: 7 bytes overhead, leaving 57 bytes per frame for payload.
const FRAME_OVERHEAD: usize = 7;

/// Chunk size: payload bytes per frame = FRAME_SIZE - FRAME_OVERHEAD.
const CHUNK_SIZE: usize = FRAME_SIZE - FRAME_OVERHEAD;

// Compile-time assertions: guard the CHUNK_SIZE arithmetic so a change to
// FRAME_SIZE or FRAME_OVERHEAD immediately causes a build error rather than
// silently producing wrong chunk sizes. Issue OnlyKey-tm7.
const _: () = assert!(
    CHUNK_SIZE + FRAME_OVERHEAD == FRAME_SIZE,
    "CHUNK_SIZE must equal FRAME_SIZE - FRAME_OVERHEAD"
);
const _: () = assert!(
    CHUNK_SIZE <= 255,
    "CHUNK_SIZE must fit in a u8 (used as field_byte in the last frame)"
);

/// Encode a multi-packet message for payloads that exceed a single frame (> 57 bytes).
///
/// For payloads <= 57 bytes, prefer [`HidFrame::command`] instead.
///
/// # Frame format
///
/// Each frame carries up to 57 bytes of payload starting at byte[7].
/// For non-last frames, byte[6] = `0xFF` (sentinel for "more frames follow").
/// For the last frame, byte[6] = the number of payload bytes in that frame.
///
/// # Errors
///
/// Returns [`HidError::PayloadTooLarge`] if `payload.len() > MAX_PAYLOAD` (768 bytes).
pub fn encode_large_message(
    cmd: u8,
    slot: u8,
    payload: &[u8],
) -> Result<LargeMessageFrames, HidError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(HidError::PayloadTooLarge);
    }
    let chunks: Vec<Vec<u8>> = payload.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
    Ok(LargeMessageFrames {
        cmd,
        slot,
        chunks,
        index: 0,
    })
}

/// An iterator that yields the [`HidFrame`]s for a large message.
///
/// Produced by [`encode_large_message`].
pub struct LargeMessageFrames {
    cmd: u8,
    slot: u8,
    chunks: Vec<Vec<u8>>,
    index: usize,
}

impl Iterator for LargeMessageFrames {
    type Item = HidFrame;

    fn next(&mut self) -> Option<HidFrame> {
        if self.index >= self.chunks.len() {
            return None;
        }
        let chunk = &self.chunks[self.index];
        let is_last = self.index == self.chunks.len() - 1;
        self.index += 1;

        let field_byte: u8 = if is_last { chunk.len() as u8 } else { 0xFF };

        let mut raw = [0u8; 64];
        raw[0..4].copy_from_slice(&HidFrame::HEADER);
        raw[4] = self.cmd;
        raw[5] = self.slot;
        raw[6] = field_byte;
        raw[7..7 + chunk.len()].copy_from_slice(chunk);
        Some(HidFrame::from_bytes(raw))
    }
}

impl Drop for LargeMessageFrames {
    fn drop(&mut self) {
        for chunk in &mut self.chunks {
            chunk.zeroize();
        }
    }
}

impl LargeMessageFrames {
    /// Return the total number of frames this message will produce.
    pub fn frame_count(&self) -> usize {
        self.chunks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_chunk_payload_one_frame() {
        let payload = [0xAAu8; 57];
        let frames: Vec<HidFrame> = encode_large_message(0xED, 101, &payload).unwrap().collect();
        assert_eq!(frames.len(), 1);
        let b = frames[0].as_bytes();
        assert_eq!(b[6], 57); // last frame: actual length
        assert_eq!(&b[7..64], &payload[..]);
    }

    #[test]
    fn two_chunk_payload_two_frames() {
        let payload = [0xBBu8; 58];
        let frames: Vec<HidFrame> = encode_large_message(0xED, 101, &payload).unwrap().collect();
        assert_eq!(frames.len(), 2);
        // First frame: non-last sentinel
        assert_eq!(frames[0].as_bytes()[6], 0xFF);
        // Second frame: 1 byte payload
        assert_eq!(frames[1].as_bytes()[6], 1);
        assert_eq!(frames[1].as_bytes()[7], 0xBB);
    }

    #[test]
    fn max_payload_succeeds() {
        let payload = [0u8; MAX_PAYLOAD];
        let result = encode_large_message(0xED, 101, &payload);
        assert!(result.is_ok());
        // ceil(768 / 57) = 14 frames (13 * 57 = 741, last = 27)
        assert_eq!(result.unwrap().frame_count(), 14);
    }

    #[test]
    fn over_max_fails() {
        let payload = [0u8; MAX_PAYLOAD + 1];
        assert!(matches!(
            encode_large_message(0xED, 101, &payload),
            Err(HidError::PayloadTooLarge)
        ));
    }

    #[test]
    fn frame_count_for_768() {
        let payload = [0u8; 768];
        let seq = encode_large_message(0xED, 101, &payload).unwrap();
        assert_eq!(seq.frame_count(), 14);
    }

    #[test]
    fn all_frames_have_correct_header() {
        let payload = [0u8; 200];
        let frames: Vec<HidFrame> = encode_large_message(0xED, 101, &payload).unwrap().collect();
        for f in &frames {
            let b = f.as_bytes();
            assert_eq!(&b[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
            assert_eq!(b[4], 0xED); // cmd
            assert_eq!(b[5], 101); // slot
        }
    }

    #[test]
    fn non_last_frames_have_ff_sentinel() {
        let payload = [0u8; 200]; // 4 frames (3 full + 1 partial)
        let frames: Vec<HidFrame> = encode_large_message(0xED, 101, &payload).unwrap().collect();
        // All but last must have 0xFF in byte[6]
        for f in &frames[..frames.len() - 1] {
            assert_eq!(f.as_bytes()[6], 0xFF);
        }
        // Last frame must have actual length
        let last_len = 200 % 57;
        assert_eq!(frames.last().unwrap().as_bytes()[6], last_len as u8);
    }
}
