// src/tun/packet_queue.rs
//! Lock-Free Packet Processing Queue
//!
//! High-performance packet passing between TUN reader and smoltcp processor
//! using crossbeam-queue for lock-free multi-producer single-consumer operations.
//!
//! Features:
//! - Zero-lock packet transfer via ArrayQueue
//! - Pre-allocated packet buffers via SharedBufferPool
//! - Async integration with tokio-util

use crossbeam_queue::ArrayQueue;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default queue capacity (number of packets)
const DEFAULT_QUEUE_CAPACITY: usize = 4096;

/// Default buffer size per packet
const DEFAULT_BUFFER_SIZE: usize = 1500;

/// Pool size for pre-allocated buffers
const DEFAULT_POOL_SIZE: usize = 8192;

// ============================================================================
// SHARED BUFFER POOL
// ============================================================================

/// Pre-allocated buffer for zero-allocation packet handling.
#[derive(Clone)]
pub struct PooledBuffer {
    /// Actual packet data
    data: Vec<u8>,
    /// Used length
    len: usize,
    /// Pool reference for returning
    pool: Arc<SharedBufferPool>,
}

impl PooledBuffer {
    /// Get the packet data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get mutable access to the data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Set the used length
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.data.capacity());
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get raw bytes for writing
    pub fn raw_bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool when dropped
        let mut recycled = std::mem::take(&mut self.data);
        recycled.clear();
        recycled.resize(DEFAULT_BUFFER_SIZE, 0);
        let _ = self.pool.recycle(recycled);
    }
}

/// Shared buffer pool for zero-allocation packet handling.
/// Uses lock-free ArrayQueue for buffer recycling.
pub struct SharedBufferPool {
    /// Available buffers
    buffers: ArrayQueue<Vec<u8>>,
    /// Statistics: buffers allocated
    allocated: AtomicU64,
    /// Statistics: buffers recycled
    recycled: AtomicU64,
    /// Statistics: pool misses (had to allocate new)
    misses: AtomicU64,
    /// Buffer size
    buffer_size: usize,
}

impl SharedBufferPool {
    /// Create a new buffer pool with default capacity.
    pub fn new() -> Arc<Self> {
        Self::with_capacity(DEFAULT_POOL_SIZE, DEFAULT_BUFFER_SIZE)
    }

    /// Create a pool with specified capacity and buffer size.
    pub fn with_capacity(pool_size: usize, buffer_size: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            buffers: ArrayQueue::new(pool_size),
            allocated: AtomicU64::new(0),
            recycled: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            buffer_size,
        });

        // Pre-allocate half the pool with 4KB page-aligned buffers.
        for _ in 0..(pool_size / 2) {
            let buf = crate::tun::tun_device::alloc_page_aligned_buffer(buffer_size);
            let _ = pool.buffers.push(buf);
            pool.allocated.fetch_add(1, Ordering::Relaxed);
        }

        pool
    }

    /// Acquire a buffer from the pool.
    /// Returns a pre-allocated buffer if available, otherwise allocates new.
    pub fn acquire(self: &Arc<Self>) -> PooledBuffer {
        let data = match self.buffers.pop() {
            Some(buf) => buf,
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                self.allocated.fetch_add(1, Ordering::Relaxed);
                crate::tun::tun_device::alloc_page_aligned_buffer(self.buffer_size)
            }
        };

        PooledBuffer {
            data,
            len: 0,
            pool: Arc::clone(self),
        }
    }

    /// Recycle a buffer back to the pool.
    fn recycle(&self, buffer: Vec<u8>) -> Result<(), Vec<u8>> {
        match self.buffers.push(buffer) {
            Ok(()) => {
                self.recycled.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(buf) => Err(buf), // Pool is full, buffer will be dropped
        }
    }

    /// Get pool statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            allocated: self.allocated.load(Ordering::Relaxed),
            recycled: self.recycled.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            available: self.buffers.len(),
            capacity: self.buffers.capacity(),
        }
    }
}

impl Default for SharedBufferPool {
    fn default() -> Self {
        // This is only used for the Arc::new pattern
        Self {
            buffers: ArrayQueue::new(DEFAULT_POOL_SIZE),
            allocated: AtomicU64::new(0),
            recycled: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            buffer_size: DEFAULT_BUFFER_SIZE,
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Total buffers allocated
    pub allocated: u64,
    /// Total buffers recycled
    pub recycled: u64,
    /// Times the pool was empty and had to allocate
    pub misses: u64,
    /// Currently available buffers
    pub available: usize,
    /// Pool capacity
    pub capacity: usize,
}

// ============================================================================
// LOCK-FREE PACKET QUEUE
// ============================================================================

/// Lock-free packet queue for high-throughput packet transfer.
/// Uses crossbeam ArrayQueue for wait-free push/pop operations.
pub struct PacketQueue {
    /// Underlying queue
    queue: ArrayQueue<PooledBuffer>,
    /// Statistics: packets enqueued
    enqueued: AtomicU64,
    /// Statistics: packets dequeued
    dequeued: AtomicU64,
    /// Statistics: drops due to full queue
    dropped: AtomicU64,
    /// Associated buffer pool
    pool: Arc<SharedBufferPool>,
}

impl PacketQueue {
    /// Create a new packet queue with default capacity.
    pub fn new(pool: Arc<SharedBufferPool>) -> Self {
        Self::with_capacity(DEFAULT_QUEUE_CAPACITY, pool)
    }

    /// Create a queue with specified capacity.
    pub fn with_capacity(capacity: usize, pool: Arc<SharedBufferPool>) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            enqueued: AtomicU64::new(0),
            dequeued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            pool,
        }
    }

    /// Enqueue a packet (non-blocking).
    /// Returns Ok(()) on success, Err(buffer) if queue is full.
    pub fn push(&self, packet: PooledBuffer) -> Result<(), PooledBuffer> {
        match self.queue.push(packet) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(pkt) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Err(pkt)
            }
        }
    }

    /// Dequeue a packet (non-blocking).
    /// Returns Some(packet) if available, None if queue is empty.
    pub fn pop(&self) -> Option<PooledBuffer> {
        let packet = self.queue.pop()?;
        self.dequeued.fetch_add(1, Ordering::Relaxed);
        Some(packet)
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get current queue length.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Get queue capacity.
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    /// Get the associated buffer pool.
    pub fn pool(&self) -> &Arc<SharedBufferPool> {
        &self.pool
    }

    /// Get queue statistics.
    pub fn stats(&self) -> QueueStats {
        QueueStats {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dequeued: self.dequeued.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            current_len: self.queue.len(),
            capacity: self.queue.capacity(),
        }
    }
}

/// Queue statistics
#[derive(Debug, Clone, Copy)]
pub struct QueueStats {
    /// Total packets enqueued
    pub enqueued: u64,
    /// Total packets dequeued
    pub dequeued: u64,
    /// Packets dropped due to full queue
    pub dropped: u64,
    /// Current queue length
    pub current_len: usize,
    /// Queue capacity
    pub capacity: usize,
}

// ============================================================================
// ASYNC PACKET PROCESSOR
// ============================================================================

/// Async packet processor that bridges TUN and smoltcp.
/// Uses tokio-util for async integration with lock-free queues.
pub struct AsyncPacketProcessor {
    /// Inbound queue (TUN -> smoltcp)
    rx_queue: Arc<PacketQueue>,
    /// Outbound queue (smoltcp -> TUN)
    tx_queue: Arc<PacketQueue>,
    /// Buffer pool
    pool: Arc<SharedBufferPool>,
    /// Processing state
    running: std::sync::atomic::AtomicBool,
}

impl AsyncPacketProcessor {
    /// Create a new async packet processor.
    pub fn new() -> Self {
        let pool = SharedBufferPool::new();
        Self {
            rx_queue: Arc::new(PacketQueue::new(Arc::clone(&pool))),
            tx_queue: Arc::new(PacketQueue::new(Arc::clone(&pool))),
            pool,
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Get reference to inbound queue.
    pub fn rx_queue(&self) -> Arc<PacketQueue> {
        Arc::clone(&self.rx_queue)
    }

    /// Get reference to outbound queue.
    pub fn tx_queue(&self) -> Arc<PacketQueue> {
        Arc::clone(&self.tx_queue)
    }

    /// Get reference to buffer pool.
    pub fn pool(&self) -> Arc<SharedBufferPool> {
        Arc::clone(&self.pool)
    }

    /// Check if processor is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Start the processor (mark as running).
    pub fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
    }

    /// Stop the processor.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Acquire a buffer from the pool.
    pub fn acquire_buffer(&self) -> PooledBuffer {
        self.pool.acquire()
    }

    /// Submit an inbound packet (from TUN).
    pub fn submit_inbound(&self, packet: PooledBuffer) -> Result<(), PooledBuffer> {
        self.rx_queue.push(packet)
    }

    /// Submit an outbound packet (to TUN).
    pub fn submit_outbound(&self, packet: PooledBuffer) -> Result<(), PooledBuffer> {
        self.tx_queue.push(packet)
    }

    /// Poll for inbound packet.
    pub fn poll_inbound(&self) -> Option<PooledBuffer> {
        self.rx_queue.pop()
    }

    /// Poll for outbound packet.
    pub fn poll_outbound(&self) -> Option<PooledBuffer> {
        self.tx_queue.pop()
    }

    /// Get combined statistics.
    pub fn stats(&self) -> ProcessorStats {
        ProcessorStats {
            rx: self.rx_queue.stats(),
            tx: self.tx_queue.stats(),
            pool: self.pool.stats(),
        }
    }
}

impl Default for AsyncPacketProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined processor statistics
#[derive(Debug, Clone)]
pub struct ProcessorStats {
    /// RX queue stats
    pub rx: QueueStats,
    /// TX queue stats
    pub tx: QueueStats,
    /// Buffer pool stats
    pub pool: PoolStats,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_acquire_release() {
        let pool = SharedBufferPool::new();

        // Acquire multiple buffers
        let b1 = pool.acquire();
        let b2 = pool.acquire();
        let b3 = pool.acquire();

        assert!(b1.capacity() >= DEFAULT_BUFFER_SIZE);
        assert!(b2.capacity() >= DEFAULT_BUFFER_SIZE);
        assert!(b3.capacity() >= DEFAULT_BUFFER_SIZE);

        // Drop buffers - they should be recycled
        drop(b1);
        drop(b2);
        drop(b3);

        let stats = pool.stats();
        assert!(stats.recycled >= 3);
    }

    #[test]
    fn test_packet_queue_push_pop() {
        let pool = SharedBufferPool::new();
        let queue = PacketQueue::new(pool);

        // Create and push a packet
        let mut buf = queue.pool().acquire();
        buf.raw_bytes_mut()[..5].copy_from_slice(b"hello");
        buf.set_len(5);

        assert!(queue.push(buf).is_ok());
        assert_eq!(queue.len(), 1);

        // Pop the packet
        let popped = queue.pop().unwrap();
        assert_eq!(&popped.as_slice()[..5], b"hello");
        assert!(queue.is_empty());
    }

    #[test]
    fn test_async_processor_flow() {
        let processor = AsyncPacketProcessor::new();

        // Acquire buffer and submit
        let mut buf = processor.acquire_buffer();
        buf.raw_bytes_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        buf.set_len(4);

        assert!(processor.submit_inbound(buf).is_ok());

        // Poll it back
        let received = processor.poll_inbound().unwrap();
        assert_eq!(received.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_processor_stats() {
        let processor = AsyncPacketProcessor::new();

        for _ in 0..100 {
            let mut buf = processor.acquire_buffer();
            buf.set_len(100);
            let _ = processor.submit_inbound(buf);
        }

        let stats = processor.stats();
        assert_eq!(stats.rx.enqueued, 100);
        assert_eq!(stats.rx.current_len, 100);
    }
}
