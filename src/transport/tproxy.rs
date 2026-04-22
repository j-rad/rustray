use crate::error::Result;
#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
pub fn create_tproxy_socket(addr: &SocketAddr, ipv6: bool) -> Result<tokio::net::UdpSocket> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Set IP_TRANSPARENT (constant is 19 on Linux usually, but better use libc or socket2 define if available)
    // socket2 0.4+ might have it or via setsockopt
    // socket.set_ip_transparent(true)?; // Check if socket2 supports this directly

    // If socket2 doesn't have set_ip_transparent, we use libc
    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // Also enable REUSEADDR
        socket.set_reuse_address(true)?;

        // Set IP_RECVORIGDSTADDR to get original destination
        if ipv6 {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
        } else {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_RECVORIGDSTADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
        }
    }

    socket.set_nonblocking(true)?;
    socket.bind(&(*addr).into())?;

    let udp = tokio::net::UdpSocket::from_std(socket.into())?;
    Ok(udp)
}

#[cfg(not(target_os = "linux"))]
pub fn create_tproxy_socket(
    _addr: &std::net::SocketAddr,
    _ipv6: bool,
) -> Result<tokio::net::UdpSocket> {
    Err(anyhow::anyhow!("TProxy only supported on Linux"))
}

#[cfg(target_os = "linux")]
pub fn recv_from_with_orig_dst(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    // We need to use recvmsg with cmsg to get ORIGDSTADDR
    // Rust's UdpSocket doesn't expose recvmsg easily with cmsg.
    // We can use socket2 or direct libc calls or nix.
    // Or we use AsyncFd to poll readability and then perform raw recvmsg.

    let fd = socket.as_raw_fd();
    let mut iov = [libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    }];

    // CMSG buffer
    let mut cmsg = [0u8; 64];
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    msghdr.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msghdr.msg_iov = iov.as_mut_ptr();
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = cmsg.len() as _;

    // Check readiness using poll_recv?
    // Since we are called from async context on a tokio socket,
    // ideally we should use tokio's async reading.
    // But standard `recv_from` doesn't give control message.

    // Simpler approach: Use `socket.try_io` logic?
    // Or just implement a synchronous recvmsg inside `block_in_place`? No, bad for async.

    // We can use `tokio::net::UdpSocket::try_io` (if public? no)
    // We can assume readiness was checked by caller? No.

    // Let's implement a wrapper struct `TProxyUdpSocket`?
    // For now, let's just do a blocking call if we are sure it's readable,
    // or better: `socket.readable().await?`.

    // But we are inside a function, not async.
    // The caller should await readiness.

    // Let's assume the caller uses `socket.recv_msg`? Tokio doesn't support it fully yet for cmsg.

    // We will use raw libc recvmsg. The socket is non-blocking.

    let ret = unsafe { libc::recvmsg(fd, &mut msghdr, 0) };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let n = ret as usize;
    let src = unsafe { sockaddr_to_socket_addr(&src_addr)? };
    let orig_dst = unsafe { parse_orig_dst(&msghdr) };

    Ok((n, src, orig_dst))
}

#[cfg(target_os = "linux")]
unsafe fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match storage.ss_family as i32 {
        libc::AF_INET => unsafe {
            let addr: &libc::sockaddr_in = std::mem::transmute(storage);
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        },
        libc::AF_INET6 => unsafe {
            let addr: &libc::sockaddr_in6 = std::mem::transmute(storage);
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
        },
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid address family",
        )),
    }
}

#[cfg(target_os = "linux")]
unsafe fn parse_orig_dst(msghdr: &libc::msghdr) -> Option<SocketAddr> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msghdr) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_ORIGDSTADDR {
                let addr_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let addr = *addr_ptr;
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                let port = u16::from_be(addr.sin_port);
                return Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
            } else if (*cmsg).cmsg_level == libc::SOL_IPV6
                && (*cmsg).cmsg_type == libc::IPV6_ORIGDSTADDR
            {
                let addr_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let addr = *addr_ptr;
                let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                let port = u16::from_be(addr.sin6_port);
                return Some(SocketAddr::new(std::net::IpAddr::V6(ip), port));
            }
            cmsg = libc::CMSG_NXTHDR(msghdr, cmsg);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub fn recv_from_with_orig_dst(
    _socket: &tokio::net::UdpSocket,
    _buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Option<std::net::SocketAddr>)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Not supported",
    ))
}
