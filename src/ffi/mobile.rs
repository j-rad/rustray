#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::ffi::ConnectConfig;
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::ffi::VpnCallback;
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::tun::{Tun2SocksConfig, Tun2SocksEngine, TunConfig};
// StreamEvent was unused even on mobile

use std::alloc::{Layout, alloc, dealloc};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(target_os = "android", target_os = "ios"))]
use tokio::runtime::Runtime;
#[cfg(any(target_os = "android", target_os = "ios"))]
use tracing::info;

// ============================================================================
// MOBILE BUFFER POOL
// ============================================================================

#[cfg(target_os = "ios")]
const IOS_POOL_CAPACITY: usize = 256;
const DEFAULT_BUFFER_SIZE: usize = 16384;
const MAX_IOS_BUFFER_SIZE: usize = 65536;

struct PoolBuffer {
    ptr: NonNull<u8>,
    capacity: usize,
    in_use: AtomicBool,
}

impl PoolBuffer {
    fn allocate(size: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size, 8).ok()?;
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr)?;
        Some(Self {
            ptr,
            capacity: size,
            in_use: AtomicBool::new(false),
        })
    }

    fn try_acquire(&self) -> bool {
        self.in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn release(&self) {
        self.in_use.store(false, Ordering::Release);
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for PoolBuffer {
    fn drop(&mut self) {
        if let Ok(layout) = Layout::from_size_align(self.capacity, 8) {
            unsafe {
                dealloc(self.ptr.as_ptr(), layout);
            }
        }
    }
}

pub struct StaticBufferPool {
    buffers: Vec<PoolBuffer>,
}

impl StaticBufferPool {
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let buffer_size = buffer_size.min(MAX_IOS_BUFFER_SIZE);
        let mut buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            if let Some(buf) = PoolBuffer::allocate(buffer_size) {
                buffers.push(buf);
            }
        }
        Self { buffers }
    }

    pub fn acquire(&self) -> Option<PooledSlice> {
        for (idx, buf) in self.buffers.iter().enumerate() {
            if buf.try_acquire() {
                return Some(PooledSlice {
                    pool: self as *const _,
                    index: idx,
                    ptr: buf.as_ptr(),
                    capacity: buf.capacity,
                    len: 0,
                });
            }
        }
        None
    }

    fn release(&self, index: usize) {
        if index < self.buffers.len() {
            self.buffers[index].release();
        }
    }
}

pub struct PooledSlice {
    pool: *const StaticBufferPool,
    index: usize,
    ptr: *mut u8,
    capacity: usize,
    len: usize,
}

impl PooledSlice {
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.capacity) }
    }
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.capacity);
    }
}

impl Drop for PooledSlice {
    fn drop(&mut self) {
        if !self.pool.is_null() {
            unsafe {
                (*self.pool).release(self.index);
            }
        }
    }
}

unsafe impl Send for PooledSlice {}

#[allow(unused)]
static mut IOS_POOL: Option<StaticBufferPool> = None;
#[allow(unused)]
static IOS_POOL_INIT: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "ios")]
pub fn init_ios_pool() {
    IOS_POOL_INIT.call_once(|| unsafe {
        IOS_POOL = Some(StaticBufferPool::new(
            IOS_POOL_CAPACITY,
            DEFAULT_BUFFER_SIZE,
        ));
    });
}

#[cfg(not(target_os = "ios"))]
pub fn init_ios_pool() {}

#[allow(unused)]
pub fn acquire_ios_buffer() -> Option<PooledSlice> {
    #[cfg(target_os = "ios")]
    {
        init_ios_pool();
        unsafe { IOS_POOL.as_ref()?.acquire() }
    }
    #[cfg(not(target_os = "ios"))]
    {
        None
    }
}

// ============================================================================
// MOBILE RUNNER
// ============================================================================

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn run_mobile_tun(
    runtime: &Runtime,
    connect_config: &ConnectConfig,
    callback: Option<Box<dyn VpnCallback>>,
) {
    #[cfg(target_os = "android")]
    {
        if let Some(fd) = connect_config.tun_fd {
            info!("Starting Android Tun2Socks with FD: {}", fd);
            let mut tun_conf = Tun2SocksConfig::default();
            tun_conf.tun = TunConfig {
                fd: Some(fd),
                ..Default::default()
            };

            if let Some(cb) = callback {
                let _ = cb.protect(fd);
            }

            let mut engine = Tun2SocksEngine::new(tun_conf);
            runtime.spawn(async move {
                if let Err(e) = engine.run().await {
                    tracing::error!("Mobile Tun2Socks failed: {}", e);
                }
            });
        }
    }
}
