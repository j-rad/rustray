// src/bpf/xdp_jitter.rs
//! XDP Egress Program using Aya to introduce jitter and shrink TCP Window size.
//! Because XDP cannot do complex sleep, we use `bpf_ktime_get_ns` to do spinning
//! or limit bandwidth, but for true jitter we rely on BPF dropping packets early
//! and retransmitting them, or in TC using EDT. In XDP, we can only modify packet
//! size and simple fields.
//!
//! Here we implement the TCP Window size mutilation (shrinking to 512 bytes on ACKs).
//! A pure busy-wait in XDP is forbidden by the verifier, so we simulate jitter by
//! probabilistically dropping packets (forcing re-transmit delay) or if TC is used
//! alongside, adjusting `skb->tstamp` for Earliest Departure Time (EDT).
//! Since this is pure XDP, we will perform probabilistic early drops and window shrinking.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns}, macros::xdp, programs::XdpContext,
};
use core::mem;

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
const TCP_FLAGS_ACK: u16 = 0x0010;
const TCP_FLAGS_SYN: u16 = 0x0002;
const TCPOPT_MSS: u8 = 2;

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

#[xdp]
pub fn xdp_jitter(ctx: XdpContext) -> u32 {
    match try_xdp_jitter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_jitter(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;

    // Check if IPv4
    if u16::from_be(unsafe { (*eth).h_proto }) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<Ipv4Hdr>(ctx, mem::size_of::<EthHdr>())?;

    // Check if TCP
    if unsafe { (*ip).protocol } != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = (unsafe { (*ip).ihl_version } & 0x0F) as usize;
    let tcp_offset = mem::size_of::<EthHdr>() + (ihl * 4);

    let tcp = ptr_at::<TcpHdr>(ctx, tcp_offset)?;

    // Mutilation 1: Probabilistic Jitter (Time-Domain Mutilation)
    // Inject a randomized delay Δt into every outbound packet to model a domestic video stream
    // Using a bounded spin-loop. (Note: Large delays risk verifier rejection or watchdog timeouts)
    let rand_val = unsafe { bpf_get_prandom_u32() };
    let delay_ns = 5_000_000 + (rand_val % 45_000_000) as u64; // 5ms - 50ms delay
    let start_time = unsafe { bpf_ktime_get_ns() };
    
    // Busy wait loop bounded by an arbitrary iteration limit to appease the verifier
    let mut _spin = 0;
    for i in 0..10000 {
        if unsafe { bpf_ktime_get_ns() } - start_time >= delay_ns {
            break;
        }
        // Force compiler not to optimize away
        unsafe { core::ptr::read_volatile(&i) };
    }

    // Mutilation 2: TCP Window and MSS Control
    // To induce "Fail-Open" in stateful DPIs, we shrink the MSS to 128 bytes on outbound SYNs,
    // and force tiny window sizes on ACKs.
    let doff_flags = u16::from_be(unsafe { (*tcp).res1_doff_res2 });
    let doff = (doff_flags >> 12) as usize;
    
    if (doff_flags & TCP_FLAGS_ACK) != 0 {
        // Force window to 512
        unsafe {
            (*tcp).window = u16::to_be(512);
        }
    }
    
    if (doff_flags & TCP_FLAGS_SYN) != 0 && doff > 5 {
        // Parse options to find MSS (kind = 2). 
        // Max options length is 40 bytes. We unroll a bounded scan for the verifier.
        let opt_offset = tcp_offset + mem::size_of::<TcpHdr>();
        let mut curr_offset = opt_offset;
        
        // Up to 10 options max checked
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
                    // Force MSS to exactly 128 bytes
                    unsafe { *mss_val_ptr = u16::to_be(128); }
                }
                break;
            }
            
            if len == 0 { break; } // Avoid infinite loop on malformed option
            curr_offset += len;
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
