#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz VLESS protocol parser
    // VLESS header format:
    // [Version:1][UUID:16][AddonsLength:1][Addons:...][Command:1][Port:2][AddrType:1][Addr:...][Padding:...]

    if data.len() < 20 {
        return; // Too short to be valid
    }

    // Try to parse version
    let version = data[0];
    if version != 0 {
        return; // Invalid version
    }

    // Extract UUID (16 bytes)
    let uuid_bytes = &data[1..17];

    // Try to parse UUID
    let _ = uuid::Uuid::from_slice(uuid_bytes);

    // Parse addons length
    if data.len() < 18 {
        return;
    }
    let addons_len = data[17] as usize;

    // Check if we have enough data for addons
    if data.len() < 18 + addons_len {
        return;
    }

    // Skip addons and parse command
    let cmd_offset = 18 + addons_len;
    if data.len() <= cmd_offset {
        return;
    }
    let _command = data[cmd_offset];

    // Parse port (2 bytes, big-endian)
    if data.len() < cmd_offset + 3 {
        return;
    }
    let _port = u16::from_be_bytes([data[cmd_offset + 1], data[cmd_offset + 2]]);

    // Parse address type
    if data.len() < cmd_offset + 4 {
        return;
    }
    let addr_type = data[cmd_offset + 3];

    // Parse address based on type
    match addr_type {
        1 => {
            // IPv4 (4 bytes)
            if data.len() < cmd_offset + 8 {
                return;
            }
            let _ipv4 = &data[cmd_offset + 4..cmd_offset + 8];
        }
        2 => {
            // Domain (length-prefixed)
            if data.len() < cmd_offset + 5 {
                return;
            }
            let domain_len = data[cmd_offset + 4] as usize;
            if data.len() < cmd_offset + 5 + domain_len {
                return;
            }
            let _domain = &data[cmd_offset + 5..cmd_offset + 5 + domain_len];

            // Try to parse as UTF-8
            let _ = std::str::from_utf8(_domain);
        }
        3 => {
            // IPv6 (16 bytes)
            if data.len() < cmd_offset + 20 {
                return;
            }
            let _ipv6 = &data[cmd_offset + 4..cmd_offset + 20];
        }
        _ => {
            // Invalid address type
            return;
        }
    }

    // If we got here, the header parsed successfully
    // In a real implementation, this would trigger actual protocol handling
});
