#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_prandom_u32},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;

// --- Constants & Types ---

#[allow(non_camel_case_types)]
type __u8 = u8;
#[allow(non_camel_case_types)]
type __u16 = u16;

#[repr(C)]
struct EthHdr {
    h_dest: [__u8; 6],
    h_source: [__u8; 6],
    h_proto: __u16,
}

#[repr(C)]
struct Ipv4Hdr {
    ihl_version: __u8,
    tos: __u8,
    tot_len: __u16,
    id: __u16,
    frag_off: __u16,
    ttl: __u8,
    protocol: __u8,
    check: __u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
struct TcpHdr {
    source: __u16,
    dest: __u16,
    seq: u32,
    ack_seq: u32,
    res1_doff_res2: __u16,
    window: __u16,
    check: __u16,
    urg_ptr: __u16,
}

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const TCP_FLAGS_SYN: u16 = 0x0002;
const TCPOPT_MSS: u8 = 2;

// --- Maps ---

#[map(name = "GHOST_MSS_CONFIG")]
static mut GHOST_MSS_CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(2, 0);

#[map(name = "GHOST_WHITELIST")]
static mut GHOST_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// --- Helpers ---

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

/// Compute the RFC 1624 incremental TCP checksum update.
/// `HC' = ~(~HC + ~m + m')`
#[inline(always)]
fn rfc1624_checksum_update(old_check: u16, old_word: u16, new_word: u16) -> u16 {
    let hc = !old_check as u32;
    let m = !old_word as u32;
    let m_prime = new_word as u32;
    let sum = hc.wrapping_add(m).wrapping_add(m_prime);
    let folded = (sum & 0xFFFF) + (sum >> 16);
    let folded = (folded & 0xFFFF) + (folded >> 16);
    !(folded as u16)
}

// --- Main XDP Logic ---

#[xdp]
pub fn xdp_ghoststream(ctx: XdpContext) -> u32 {
    match try_xdp_ghoststream(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_ghoststream(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;

    // Only process IPv4
    if u16::from_be(unsafe { (*eth).h_proto }) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<Ipv4Hdr>(ctx, mem::size_of::<EthHdr>())?;
    
    // Only process TCP
    if unsafe { (*ip).protocol } != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let daddr = u32::from_be(unsafe { (*ip).daddr });

    // Check whitelist map: if empty or target not found, PASS.
    // If target is found (value == 1), we apply fragmentation logic.
    let is_whitelisted = unsafe { GHOST_WHITELIST.get(&daddr) }.map(|v| *v == 1).unwrap_or(false);
    
    if !is_whitelisted {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = (unsafe { (*ip).ihl_version } & 0x0F) as usize;
    let tcp_offset = mem::size_of::<EthHdr>() + (ihl * 4);
    let tcp = ptr_at::<TcpHdr>(ctx, tcp_offset)?;

    let doff_flags = u16::from_be(unsafe { (*tcp).res1_doff_res2 });
    let doff = (doff_flags >> 12) as usize;

    // Only process SYN packets
    if (doff_flags & TCP_FLAGS_SYN) == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Only process if there are TCP options
    if doff <= 5 {
        return Ok(xdp_action::XDP_PASS);
    }

    let mut mss_min = 64u16;
    let mut mss_max = 128u16;

    if let Some(&min_val) = unsafe { GHOST_MSS_CONFIG.get(&0) } {
        mss_min = min_val as u16;
    }
    if let Some(&max_val) = unsafe { GHOST_MSS_CONFIG.get(&1) } {
        mss_max = max_val as u16;
    }
    
    // Clamp to boundaries if bad configuration
    if mss_min < 64 { mss_min = 64; }
    if mss_max > 1500 { mss_max = 1500; }
    if mss_min > mss_max { mss_min = mss_max; }

    let opt_offset = tcp_offset + mem::size_of::<TcpHdr>();
    let mut curr_offset = opt_offset;

    // Parse options to find MSS (kind = 2)
    for _ in 0..10 {
        if curr_offset >= opt_offset + 40 { break; }
        
        let kind_ptr = match ptr_at::<u8>(ctx, curr_offset) {
            Ok(ptr) => ptr,
            Err(_) => break,
        };
        
        let kind = unsafe { *kind_ptr };
        if kind == 0 { break; } // EOL
        if kind == 1 { // NOP
            curr_offset += 1;
            continue;
        }
        
        let len_ptr = match ptr_at::<u8>(ctx, curr_offset + 1) {
            Ok(ptr) => ptr,
            Err(_) => break,
        };
        let len = unsafe { *len_ptr } as usize;
        
        if kind == TCPOPT_MSS && len == 4 {
            if let Ok(mss_val_ptr) = ptr_at::<u16>(ctx, curr_offset + 2) {
                let old_mss = u16::from_be(unsafe { *mss_val_ptr });
                
                let range = mss_max - mss_min + 1;
                let rand_val = unsafe { bpf_get_prandom_u32() };
                let target_mss = mss_min + (rand_val % range as u32) as u16;
                
                // Only clamp if current MSS is larger than our target
                if old_mss > target_mss {
                    let old_check = u16::from_be(unsafe { (*tcp).check });
                    
                    unsafe { *mss_val_ptr = u16::to_be(target_mss); }
                    
                    let new_check = rfc1624_checksum_update(old_check, old_mss, target_mss);
                    unsafe { (*tcp).check = u16::to_be(new_check); }
                }
            }
            break;
        }
        
        if len == 0 { break; } // Avoid infinite loop
        curr_offset += len;
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
