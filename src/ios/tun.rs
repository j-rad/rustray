// src/ios/tun.rs
//! iOS TUN Device Integration for NetworkExtension
//!
//! This module provides a wrapper around the file descriptor passed from
//! iOS's NEPacketTunnelProvider to create a TUN device for packet routing.

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use tracing::{debug, info, warn};

/// iOS TUN device wrapper
pub struct IosTunDevice {
    fd: RawFd,
    file: std::fs::File,
}

impl IosTunDevice {
    /// Create a TUN device from a file descriptor
    ///
    /// # Safety
    /// The fd must be a valid file descriptor from NEPacketTunnelProvider
    pub unsafe fn from_raw_fd(fd: RawFd) -> std::io::Result<Self> {
        info!("Creating iOS TUN device from fd={}", fd);

        let file = std::fs::File::from_raw_fd(fd);

        Ok(Self { fd, file })
    }

    /// Read a packet from the TUN device
    pub fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }

    /// Write a packet to the TUN device
    pub fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.file.write(packet)
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Close the TUN device
    pub fn close(self) -> std::io::Result<()> {
        debug!("Closing iOS TUN device fd={}", self.fd);
        drop(self.file);
        Ok(())
    }
}

impl AsRawFd for IosTunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for IosTunDevice {
    fn drop(&mut self) {
        debug!("Dropping iOS TUN device fd={}", self.fd);
    }
}

/// Create a TUN device from the file descriptor passed via FFI
///
/// # Arguments
/// * `fd` - File descriptor from iOS NEPacketTunnelProvider
///
/// # Returns
/// * `Result<IosTunDevice>` - TUN device wrapper
///
/// # Safety
/// The fd must be valid and owned by this process
pub fn create_tun_from_fd(fd: i32) -> std::io::Result<IosTunDevice> {
    if fd < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid file descriptor",
        ));
    }

    unsafe { IosTunDevice::from_raw_fd(fd) }
}

/// Global TUN device handle for kill switch
static mut GLOBAL_TUN_FD: Option<RawFd> = None;

/// Set the global TUN FD for emergency shutdown
pub fn set_global_tun_fd(fd: RawFd) {
    unsafe {
        GLOBAL_TUN_FD = Some(fd);
    }
}

/// Emergency TUN interface destruction
pub fn destroy_tun_interface() {
    unsafe {
        if let Some(fd) = GLOBAL_TUN_FD {
            warn!("EMERGENCY: Destroying TUN interface fd={}", fd);
            libc::close(fd);
            GLOBAL_TUN_FD = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_fd() {
        let result = create_tun_from_fd(-1);
        assert!(result.is_err());
    }
}
