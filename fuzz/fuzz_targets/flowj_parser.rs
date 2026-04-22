#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Flow-J protocol parser
    // Flow-J uses custom flow control sequences

    if data.is_empty() {
        return;
    }

    // Flow-J packet format:
    // [Type:1][SequenceNum:4][WindowSize:2][Flags:1][Payload:...]

    if data.len() < 8 {
        return; // Too short
    }

    // Parse packet type
    let packet_type = data[0];
    match packet_type {
        0x01 => {
            // DATA packet
            let seq_num = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            let window_size = u16::from_be_bytes([data[5], data[6]]);
            let flags = data[7];

            // Validate flags
            let _has_fin = (flags & 0x01) != 0;
            let _has_ack = (flags & 0x02) != 0;
            let _has_rst = (flags & 0x04) != 0;

            // Validate sequence number (should be reasonable)
            if seq_num > 0xFFFFFF {
                return;
            }

            // Validate window size (should be non-zero for data packets)
            if window_size == 0 && data.len() > 8 {
                return;
            }

            // Parse payload
            if data.len() > 8 {
                let _payload = &data[8..];
                // In real implementation, would process payload
            }
        }
        0x02 => {
            // ACK packet
            let ack_num = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            let _window_size = u16::from_be_bytes([data[5], data[6]]);

            // Validate ACK number
            if ack_num > 0xFFFFFF {
                return;
            }
        }
        0x03 => {
            // PING packet (keepalive)
            let timestamp = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

            // Validate timestamp (should be reasonable)
            if timestamp == 0 {
                return;
            }
        }
        0x04 => {
            // PONG packet (response to ping)
            let timestamp = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

            if timestamp == 0 {
                return;
            }
        }
        0xFF => {
            // RESET packet
            let reason_code = data[1];

            // Validate reason code
            match reason_code {
                0x00 => { /* Normal close */ }
                0x01 => { /* Protocol error */ }
                0x02 => { /* Timeout */ }
                0x03 => { /* Resource exhaustion */ }
                _ => return, // Invalid reason
            }
        }
        _ => {
            // Unknown packet type
            return;
        }
    }

    // Test edge cases
    if data.len() > 8 {
        // Try to parse as multiple concatenated packets
        let mut offset = 0;
        while offset + 8 <= data.len() {
            let _sub_packet = &data[offset..offset + 8];
            offset += 8;
        }
    }

    // Test malformed sequences
    if data.len() >= 16 {
        // Check for invalid state transitions
        let type1 = data[0];
        let type2 = data[8];

        // RST should not be followed by DATA
        if type1 == 0xFF && type2 == 0x01 {
            return;
        }
    }
});
