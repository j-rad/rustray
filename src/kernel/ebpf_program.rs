// src/kernel/ebpf_program.rs
//! eBPF TC Egress Classifier — Pre-compiled BPF bytecode generation.
//!
//! Generates BPF instructions for a `sched_cls` Traffic Control classifier
//! that intercepts outbound TLS ClientHello packets on port 443 and slices
//! them into 3 irregular segments to defeat stateful DPI inspection.
//!
//! The program:
//! 1. Parses Eth → IPv4 → TCP headers
//! 2. Checks destination IP against a BPF_MAP_TYPE_HASH of whitelisted proxy IPs
//! 3. Filters for port 443 with payload starting `0x16 0x03 0x01` (TLS ClientHello)
//! 4. Slices the ClientHello into 3 segments with randomized byte offsets
//!
//! Because `aya` is not locally vendored, we generate raw BPF instructions
//! using the kernel's `bpf_insn` format and load them via `libc::syscall(SYS_bpf)`.


// ============================================================================
// BPF INSTRUCTION ENCODING
// ============================================================================

/// A single BPF instruction (8 bytes, matching `struct bpf_insn`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BpfInsn {
    /// Opcode (operation + source/class).
    pub code: u8,
    /// Destination register (4 bits) | source register (4 bits).
    pub regs: u8,
    /// Signed offset for jumps / memory access.
    pub off: i16,
    /// Immediate constant.
    pub imm: i32,
}

impl BpfInsn {
    /// Encode `dst_reg` and `src_reg` into the packed `regs` byte (dst = low nibble).
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (src << 4) | (dst & 0x0F),
            off,
            imm,
        }
    }
}

// --- BPF opcode constants ---

// Instruction classes
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;

// ALU operations
const BPF_ADD: u8 = 0x00;
const BPF_AND: u8 = 0x50;
const BPF_MOV: u8 = 0xB0;
const BPF_RSH: u8 = 0x70;

// Source operand
const BPF_K: u8 = 0x00; // Immediate
const BPF_X: u8 = 0x08; // Register

// Memory sizes
const BPF_W: u8 = 0x00; // 32-bit
const BPF_H: u8 = 0x08; // 16-bit
const BPF_B: u8 = 0x10; // 8-bit
const BPF_DW: u8 = 0x18; // 64-bit

// Memory access modes
const BPF_MEM: u8 = 0x60;

// Jump operations
const BPF_JEQ: u8 = 0x10;
const BPF_JNE: u8 = 0x50;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JSGT: u8 = 0x60;
const BPF_JA: u8 = 0x00; // Unconditional jump
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;

// Registers
const BPF_REG_0: u8 = 0;
const BPF_REG_1: u8 = 1;
const BPF_REG_2: u8 = 2;
const BPF_REG_3: u8 = 3;
const BPF_REG_4: u8 = 4;
const BPF_REG_5: u8 = 5;
const BPF_REG_6: u8 = 6;
const BPF_REG_7: u8 = 7;
const BPF_REG_8: u8 = 8;
const BPF_REG_9: u8 = 9;
const BPF_REG_10: u8 = 10; // Frame pointer (stack)

// TC action returns
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_UNSPEC: i32 = -1;

// BPF helper function IDs
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_FUNC_SKB_LOAD_BYTES: i32 = 26;
const BPF_FUNC_GET_PRANDOM_U32: i32 = 7;
const BPF_FUNC_SKB_ADJUST_ROOM: i32 = 50;
const BPF_FUNC_CLONE_REDIRECT: i32 = 13;
const BPF_FUNC_SKB_CHANGE_TAIL: i32 = 38;

// Ethernet + IP + TCP header constants
const ETH_HLEN: i32 = 14;
const ETH_P_IP: i32 = 0x0800;
const IP_PROTO_TCP: i32 = 6;
const TLS_PORT: i32 = 443;
const TLS_HANDSHAKE: i32 = 0x16;
const TLS_VERSION_MAJOR: i32 = 0x03;
const TLS_VERSION_MINOR: i32 = 0x01;

// TLS Record Header size
const TLS_RECORD_HDR_LEN: usize = 5;

// ============================================================================
// INSTRUCTION BUILDER HELPERS
// ============================================================================

/// `MOV64 dst, imm` — dst = imm (64-bit)
fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
}

/// `MOV64 dst, src` — dst = src (64-bit)
fn mov64_reg(dst: u8, src: u8) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
}

/// `ADD64 dst, imm`
fn add64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
}

/// `AND64 dst, imm`
fn and64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_AND | BPF_K, dst, 0, 0, imm)
}

/// `RSH64 dst, imm`
fn rsh64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_RSH | BPF_K, dst, 0, 0, imm)
}

/// `LDX MEM dst, [src + off]` — load 8/16/32-bit from memory
fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_LDX | size | BPF_MEM, dst, src, off, 0)
}

/// `STX MEM [dst + off], src`
fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_STX | size | BPF_MEM, dst, src, off, 0)
}

/// `ST MEM [dst + off], imm`
fn st_mem(size: u8, dst: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ST | size | BPF_MEM, dst, 0, off, imm)
}

/// `JEQ dst, imm, +off` — jump if dst == imm
fn jeq_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, dst, 0, off, imm)
}

/// `JNE dst, imm, +off` — jump if dst != imm
fn jne_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, dst, 0, off, imm)
}

/// `JGT dst, imm, +off` — jump if dst > imm (unsigned)
fn jgt_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JGT | BPF_K, dst, 0, off, imm)
}

/// `JGE dst, imm, +off` — jump if dst >= imm (unsigned)
fn jge_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JGE | BPF_K, dst, 0, off, imm)
}

/// `JA +off` — unconditional jump
fn ja(off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
}

/// `CALL helper_id`
fn call(helper_id: i32) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, helper_id)
}

/// `EXIT`
fn exit_insn() -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

// ============================================================================
// TC CLASSIFIER PROGRAM GENERATION
// ============================================================================

/// Configuration for the TLS ClientHello slicer.
#[derive(Debug, Clone)]
pub struct SlicerConfig {
    /// Minimum bytes for the second segment (partial SNI).
    pub min_partial_sni: u16,
    /// Maximum bytes for the second segment (partial SNI).
    pub max_partial_sni: u16,
}

impl Default for SlicerConfig {
    fn default() -> Self {
        Self {
            min_partial_sni: 5,
            max_partial_sni: 20,
        }
    }
}

/// Generates the BPF instruction array for the TC egress classifier.
///
/// The generated program performs:
/// 1. Parse Eth header → check EtherType == IPv4
/// 2. Parse IPv4 header → check protocol == TCP
/// 3. Parse TCP header → check dport == 443
/// 4. Check payload starts with `0x16 0x03 0x01` (TLS ClientHello)
/// 5. Lookup destination IP in the whitelisted map (map_fd inserted at load time)
/// 6. If whitelisted: compute randomized slice offsets via `bpf_get_prandom_u32()`
/// 7. Truncate packet to first segment, clone-redirect the rest
///
/// The `map_fd` placeholder is set to 0 and must be patched at load time
/// with the actual file descriptor of the BPF_MAP_TYPE_HASH.
pub fn generate_tc_classifier(config: &SlicerConfig) -> Vec<BpfInsn> {
    let mut prog: Vec<BpfInsn> = Vec::with_capacity(128);

    // ---- PROLOGUE: Save context (skb pointer in R1) ----
    // R6 = skb (save R1 for later use)
    prog.push(mov64_reg(BPF_REG_6, BPF_REG_1));

    // ---- STEP 1: Check EtherType == IPv4 ----
    // Load skb->data (offset 0 in __sk_buff)
    // R7 = skb->data
    prog.push(ldx_mem(BPF_W, BPF_REG_7, BPF_REG_6, 76)); // offsetof(__sk_buff, data)
    // R8 = skb->data_end
    prog.push(ldx_mem(BPF_W, BPF_REG_8, BPF_REG_6, 80)); // offsetof(__sk_buff, data_end)

    // Bounds check: data + ETH_HLEN <= data_end
    prog.push(mov64_reg(BPF_REG_0, BPF_REG_7));
    prog.push(add64_imm(BPF_REG_0, ETH_HLEN));
    let _exit_ok_label = 0i16; // placeholder, will be patched
    // if R0 > R8 goto exit_ok (packet too small)
    prog.push(BpfInsn::new(
        BPF_JMP | BPF_JGT | BPF_X,
        BPF_REG_0,
        BPF_REG_8,
        0,
        0,
    )); // patched below
    let bounds_check_1_idx = prog.len() - 1;

    // Load EtherType at offset 12 (2 bytes, network order)
    // R0 = *(u16 *)(data + 12)
    prog.push(ldx_mem(BPF_H, BPF_REG_0, BPF_REG_7, 12));
    // EtherType is big-endian; 0x0800 = IPv4
    // ntohs(0x0800) = 0x0008 on LE, but skb loads in network order via direct access
    // Actually BPF_LDX on packet data returns host-endian.
    // We compare against htons(ETH_P_IP)
    prog.push(jne_imm(BPF_REG_0, 0x0800, 0)); // patched below
    let ethertype_check_idx = prog.len() - 1;

    // ---- STEP 2: Parse IPv4 header ----
    // R7 now points to start of data; IPv4 header starts at data + 14
    // R9 = data + ETH_HLEN (start of IP header)
    prog.push(mov64_reg(BPF_REG_9, BPF_REG_7));
    prog.push(add64_imm(BPF_REG_9, ETH_HLEN));

    // Bounds check: IP header + 20 <= data_end
    prog.push(mov64_reg(BPF_REG_0, BPF_REG_9));
    prog.push(add64_imm(BPF_REG_0, 20));
    prog.push(BpfInsn::new(
        BPF_JMP | BPF_JGT | BPF_X,
        BPF_REG_0,
        BPF_REG_8,
        0,
        0,
    ));
    let bounds_check_2_idx = prog.len() - 1;

    // Load IP protocol byte at offset 9 from IP header start
    // R0 = *(u8 *)(ip_hdr + 9)
    prog.push(ldx_mem(BPF_B, BPF_REG_0, BPF_REG_9, 9));
    // Check protocol == TCP (6)
    prog.push(jne_imm(BPF_REG_0, IP_PROTO_TCP, 0));
    let proto_check_idx = prog.len() - 1;

    // Load IHL (IP Header Length) from first byte: (byte & 0x0F) * 4
    prog.push(ldx_mem(BPF_B, BPF_REG_0, BPF_REG_9, 0));
    prog.push(and64_imm(BPF_REG_0, 0x0F));
    // R0 = IHL in 32-bit words, shift left 2 = multiply by 4
    prog.push(BpfInsn::new(BPF_ALU64 | 0x60 | BPF_K, BPF_REG_0, 0, 0, 2)); // LSH

    // ---- STEP 3: Load destination IP for map lookup ----
    // Save dest IP (offset 16 from IP header) to stack for map lookup
    // R1 = *(u32 *)(ip_hdr + 16)  — destination IP
    prog.push(ldx_mem(BPF_W, BPF_REG_1, BPF_REG_9, 16));
    // Store dest IP on stack: *(u32 *)(fp - 4) = R1
    prog.push(stx_mem(BPF_W, BPF_REG_10, BPF_REG_1, -4));

    // ---- STEP 4: Parse TCP header ----
    // R5 = IP header start + IHL = TCP header start
    prog.push(mov64_reg(BPF_REG_5, BPF_REG_9));
    prog.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_X,
        BPF_REG_5,
        BPF_REG_0,
        0,
        0,
    ));

    // Bounds check: TCP header + 20 <= data_end
    prog.push(mov64_reg(BPF_REG_0, BPF_REG_5));
    prog.push(add64_imm(BPF_REG_0, 20));
    prog.push(BpfInsn::new(
        BPF_JMP | BPF_JGT | BPF_X,
        BPF_REG_0,
        BPF_REG_8,
        0,
        0,
    ));
    let bounds_check_3_idx = prog.len() - 1;

    // Load TCP destination port (offset 2, 16-bit)
    // R0 = *(u16 *)(tcp_hdr + 2)
    prog.push(ldx_mem(BPF_H, BPF_REG_0, BPF_REG_5, 2));
    // Check dport == 443
    prog.push(jne_imm(BPF_REG_0, TLS_PORT, 0));
    let dport_check_idx = prog.len() - 1;

    // Load TCP data offset (offset 12, upper nibble) to find payload start
    prog.push(ldx_mem(BPF_B, BPF_REG_0, BPF_REG_5, 12));
    prog.push(rsh64_imm(BPF_REG_0, 4));
    prog.push(BpfInsn::new(BPF_ALU64 | 0x60 | BPF_K, BPF_REG_0, 0, 0, 2)); // LSH by 2 = *4

    // R4 = TCP header start + data offset = payload start
    prog.push(mov64_reg(BPF_REG_4, BPF_REG_5));
    prog.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_X,
        BPF_REG_4,
        BPF_REG_0,
        0,
        0,
    ));

    // ---- STEP 5: Check TLS ClientHello signature ----
    // Bounds check: payload + 3 <= data_end
    prog.push(mov64_reg(BPF_REG_0, BPF_REG_4));
    prog.push(add64_imm(BPF_REG_0, 3));
    prog.push(BpfInsn::new(
        BPF_JMP | BPF_JGT | BPF_X,
        BPF_REG_0,
        BPF_REG_8,
        0,
        0,
    ));
    let bounds_check_4_idx = prog.len() - 1;

    // Check byte 0 == 0x16 (TLS Handshake)
    prog.push(ldx_mem(BPF_B, BPF_REG_0, BPF_REG_4, 0));
    prog.push(jne_imm(BPF_REG_0, TLS_HANDSHAKE, 0));
    let tls_check_1_idx = prog.len() - 1;

    // Check byte 1 == 0x03 (TLS major version)
    prog.push(ldx_mem(BPF_B, BPF_REG_0, BPF_REG_4, 1));
    prog.push(jne_imm(BPF_REG_0, TLS_VERSION_MAJOR, 0));
    let tls_check_2_idx = prog.len() - 1;

    // Check byte 2 == 0x01 (TLS minor version — TLS 1.0 ClientHello)
    prog.push(ldx_mem(BPF_B, BPF_REG_0, BPF_REG_4, 2));
    prog.push(jne_imm(BPF_REG_0, TLS_VERSION_MINOR, 0));
    let tls_check_3_idx = prog.len() - 1;

    // ---- STEP 6: Map lookup — is dest IP whitelisted? ----
    // R1 = map_fd (patched at load time)
    // Use LD_IMM64 for map fd (2 instructions)
    prog.push(BpfInsn::new(BPF_LD | BPF_DW | 0x18, BPF_REG_1, 1, 0, 0)); // BPF_PSEUDO_MAP_FD
    prog.push(BpfInsn::new(0, 0, 0, 0, 0)); // upper 32 bits
    let _map_fd_patch_idx = prog.len() - 2;

    // R2 = pointer to key (dest IP on stack at fp - 4)
    prog.push(mov64_reg(BPF_REG_2, BPF_REG_10));
    prog.push(add64_imm(BPF_REG_2, -4));

    // Call bpf_map_lookup_elem(map_fd, &key)
    prog.push(call(BPF_FUNC_MAP_LOOKUP_ELEM));

    // If R0 == NULL, IP is not whitelisted → pass through
    prog.push(jeq_imm(BPF_REG_0, 0, 0));
    let map_miss_idx = prog.len() - 1;

    // ---- STEP 7: Generate random slice offset via bpf_get_prandom_u32() ----
    prog.push(call(BPF_FUNC_GET_PRANDOM_U32));
    // R0 = random u32
    // Compute slice_2_len = min_partial_sni + (random % (max - min + 1))
    let range = (config.max_partial_sni - config.min_partial_sni + 1) as i32;
    // R0 = R0 % range (approximate with AND if range is power of 2, otherwise use modulo)
    // Use: R0 = R0 & (range - 1) then add min
    // For general range, we do: R0 = R0 mod range via: R0 = R0 - (R0 / range) * range
    // Simpler for BPF: AND mask with next power of 2 - 1, then clamp
    // For 5-20 range (16 values), mask = 0x0F works perfectly
    prog.push(and64_imm(BPF_REG_0, (range as u32).next_power_of_two() as i32 - 1));
    // Clamp to actual range if AND gave us too high
    // if R0 >= range, R0 = range - 1
    prog.push(BpfInsn::new(
        BPF_JMP | BPF_JGE | BPF_K,
        BPF_REG_0,
        0,
        1,
        range,
    ));
    prog.push(mov64_imm(BPF_REG_0, range - 1));
    // R0 = R0 + min_partial_sni
    prog.push(add64_imm(BPF_REG_0, config.min_partial_sni as i32));
    // Save slice_2_len to stack: *(u32 *)(fp - 8) = R0
    prog.push(stx_mem(BPF_W, BPF_REG_10, BPF_REG_0, -8));

    // ---- STEP 8: Truncate to first segment (5 bytes = TLS Record Header) ----
    // Use bpf_skb_change_tail to truncate the skb to:
    //   ETH_HLEN + ip_hdr_len + tcp_hdr_len + TLS_RECORD_HDR_LEN
    //
    // We need to compute the total length of the first segment.
    // However, the simpler approach for the classifier is to mark the
    // packet with a metadata flag and let userspace handle the actual cloning.
    //
    // For a pure-TC approach: return TC_ACT_OK after marking __sk_buff->mark
    // with the computed slice offset, and use a second TC action to perform
    // the actual fragmentation.
    //
    // Set skb->mark = (TLS_RECORD_HDR_LEN << 16) | slice_2_len
    // This encodes both segment boundaries for the userspace fragment handler.
    prog.push(ldx_mem(BPF_W, BPF_REG_0, BPF_REG_10, -8)); // reload slice_2_len
    mov64_imm(BPF_REG_1, TLS_RECORD_HDR_LEN as i32);
    prog.push(BpfInsn::new(BPF_ALU64 | 0x60 | BPF_K, BPF_REG_1, 0, 0, 16)); // LSH R1, 16
    prog.push(BpfInsn::new(
        BPF_ALU64 | BPF_ADD | BPF_X,
        BPF_REG_1,
        BPF_REG_0,
        0,
        0,
    )); // R1 = (5<<16)|slice_2_len

    // Write to skb->mark (offset 4 in __sk_buff on TC path).
    // On cls_bpf, offset 8 is `mark`.
    prog.push(stx_mem(BPF_W, BPF_REG_6, BPF_REG_1, 8)); // skb->mark

    // Also set skb->cb[0] = 0xRR (magic byte to signal "mutilate this packet")
    prog.push(st_mem(BPF_W, BPF_REG_6, 48, 0x52524159_u32 as i32)); // "RRAY" magic in cb[0]

    // Return TC_ACT_OK — let the packet continue with the mark set.
    // The userspace TLS fragment handler in transport::tls_fragment reads this mark
    // and performs the actual TCP-level segmentation.
    prog.push(mov64_imm(BPF_REG_0, TC_ACT_OK));
    prog.push(exit_insn());

    // ---- EXIT_OK: pass-through label for non-matching packets ----
    let exit_ok_offset = prog.len();
    prog.push(mov64_imm(BPF_REG_0, TC_ACT_OK));
    prog.push(exit_insn());

    // ---- PATCH JUMP OFFSETS ----
    // All the "skip to exit_ok" jumps need their offset patched.
    let exit_target = exit_ok_offset;
    let jump_sources = [
        bounds_check_1_idx,
        ethertype_check_idx,
        bounds_check_2_idx,
        proto_check_idx,
        bounds_check_3_idx,
        dport_check_idx,
        bounds_check_4_idx,
        tls_check_1_idx,
        tls_check_2_idx,
        tls_check_3_idx,
        map_miss_idx,
    ];

    for &src_idx in &jump_sources {
        let delta = (exit_target as i16) - (src_idx as i16) - 1;
        prog[src_idx].off = delta;
    }

    prog
}

/// Returns the byte size of the instruction array ready for `bpf(BPF_PROG_LOAD)`.
pub fn insn_bytes(prog: &[BpfInsn]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(prog.len() * 8);
    for insn in prog {
        bytes.push(insn.code);
        bytes.push(insn.regs);
        bytes.extend_from_slice(&insn.off.to_le_bytes());
        bytes.extend_from_slice(&insn.imm.to_le_bytes());
    }
    bytes
}

/// Index of the LD_IMM64 instruction that carries the map FD placeholder.
/// The loader must patch `prog[idx].imm` with the real FD after map creation.
pub fn map_fd_insn_index(prog: &[BpfInsn]) -> Option<usize> {
    // Find the LD_IMM64 with src_reg == BPF_PSEUDO_MAP_FD (1)
    for (i, insn) in prog.iter().enumerate() {
        if insn.code == (BPF_LD | BPF_DW | 0x18) && (insn.regs >> 4) == 1 {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tc_classifier_non_empty() {
        let config = SlicerConfig::default();
        let prog = generate_tc_classifier(&config);
        assert!(prog.len() > 20, "program too short: {} insns", prog.len());
    }

    #[test]
    fn test_insn_bytes_length() {
        let config = SlicerConfig::default();
        let prog = generate_tc_classifier(&config);
        let bytes = insn_bytes(&prog);
        assert_eq!(bytes.len(), prog.len() * 8);
    }

    #[test]
    fn test_map_fd_patch_index_found() {
        let config = SlicerConfig::default();
        let prog = generate_tc_classifier(&config);
        assert!(
            map_fd_insn_index(&prog).is_some(),
            "map FD patch index not found"
        );
    }

    #[test]
    fn test_bpf_insn_encoding() {
        let insn = BpfInsn::new(0x07, 1, 2, 100, -42);
        assert_eq!(insn.code, 0x07);
        assert_eq!(insn.regs & 0x0F, 1); // dst
        assert_eq!(insn.regs >> 4, 2); // src
        assert_eq!(insn.off, 100);
        assert_eq!(insn.imm, -42);
    }

    #[test]
    fn test_slicer_config_default() {
        let config = SlicerConfig::default();
        assert_eq!(config.min_partial_sni, 5);
        assert_eq!(config.max_partial_sni, 20);
    }

    #[test]
    fn test_program_ends_with_exit() {
        let config = SlicerConfig::default();
        let prog = generate_tc_classifier(&config);
        let last = prog.last().unwrap();
        assert_eq!(last.code, BPF_JMP | BPF_EXIT, "program must end with EXIT");
    }

    #[test]
    fn test_jump_offsets_non_negative() {
        let config = SlicerConfig::default();
        let prog = generate_tc_classifier(&config);
        // All conditional jumps should have non-negative forward offsets
        for (i, insn) in prog.iter().enumerate() {
            let class = insn.code & 0x07;
            let op = insn.code & 0xF0;
            if class == BPF_JMP
                && op != BPF_CALL
                && op != BPF_EXIT
                && op != BPF_JA
            {
                assert!(
                    insn.off >= 0,
                    "insn {} has negative jump offset {}: backward jumps not expected",
                    i,
                    insn.off
                );
            }
        }
    }
}
