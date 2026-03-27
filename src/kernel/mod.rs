// src/kernel/mod.rs
//! Kernel-level eBPF subsystem for packet mutation.
//!
//! This module provides a Linux-only eBPF Traffic Control (TC) classifier
//! that dynamically slices outbound TLS ClientHello packets at the kernel
//! level to defeat stateful DPI inspection on the first packets of a session.
//!
//! The subsystem consists of:
//! - `ebpf_program`: Pre-compiled BPF bytecode and instruction generation
//! - `ebpf_loader`: Userspace manager for loading, attaching, and controlling the eBPF program

pub mod ebpf_loader;
pub mod ebpf_program;
