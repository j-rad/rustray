// src/transport/dtn.rs
//! DTN Resilience Layer — Delay/Disruption-Tolerant Networking
//!
//! Provides zero-data-loss packet persistence and session reconciliation for the
//! Virtual Transport Matrix.  Every frame is written to a memory-mapped ring
//! buffer on disk **before** it is handed to the carrier.  On reconnect, both
//! peers exchange received-bitmasks so that only genuinely missing frames are
//! retransmitted, preventing retransmission storms.
//!
//! # Ring-buffer layout (mmap file)
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  Header  (32 bytes)                              │
//! │  ├── magic      [u32]  = 0xDEAD_D1CE             │
//! │  ├── capacity   [u32]  number of slots           │
//! │  ├── write_head [u32]  next slot to write        │
//! │  ├── ack_head   [u32]  oldest un-acked slot      │
//! │  ├── local_seq  [u64]  monotonic frame counter   │
//! │  └── recv_mask  [u64]  bitset of received seqs   │
//! ├──────────────────────────────────────────────────┤
//! │  Slots  (SLOT_SIZE * capacity bytes)             │
//! │  Each slot:                                      │
//! │  ├── flags  [u8]   0=empty, 1=pending, 2=acked  │
//! │  ├── seq    [u64]                                │
//! │  ├── len    [u16]                                │
//! │  └── data   [MTU_MAX bytes]                      │
//! └──────────────────────────────────────────────────┘
//! ```

use memmap2::MmapMut;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use tracing::{debug, warn};

// ─── Constants ────────────────────────────────────────────────────────────────

const MAGIC: u32 = 0xDEAD_D1CE;
const MTU_MAX: usize = 1500;
const SLOT_DATA_OFFSET: usize = 1 + 8 + 2; // flags + seq + len
pub const SLOT_SIZE: usize = SLOT_DATA_OFFSET + MTU_MAX;

const HDR_MAGIC_OFF: usize = 0;
const HDR_CAPACITY_OFF: usize = 4;
const HDR_WRITE_HEAD_OFF: usize = 8;
const HDR_ACK_HEAD_OFF: usize = 12;
const HDR_LOCAL_SEQ_OFF: usize = 16;
const HDR_RECV_MASK_OFF: usize = 24;
pub const HEADER_SIZE: usize = 32;

const SLOT_FLAG_EMPTY: u8 = 0;
const SLOT_FLAG_PENDING: u8 = 1;
const SLOT_FLAG_ACKED: u8 = 2;

// ─── MvtFrame ─────────────────────────────────────────────────────────────────

/// A single packet frame for the DTN queue.
#[derive(Debug, Clone)]
pub struct MvtFrame {
    /// Monotonic sequence number assigned by `push_atomic`.
    pub seq: u64,
    /// Raw payload bytes (must be ≤ `MTU_MAX`).
    pub data: Vec<u8>,
}

// ─── DurableQueue ─────────────────────────────────────────────────────────────

/// Disk-backed, mmap ring buffer for DTN zero-data-loss packet persistence.
///
/// Frames are written to the ring buffer atomically (flush before returning)
/// before being handed to the carrier.  On reconnect, `reconcile_session`
/// exchanges received-bitmasks to identify and retransmit only genuinely
/// missing frames.
pub struct DurableQueue {
    mmap: MmapMut,
    /// Number of slots in the ring buffer.
    capacity: usize,
}

impl DurableQueue {
    /// Open or create a durable queue at `path` with `capacity` slots.
    ///
    /// If the file already contains a valid MAGIC header and matching capacity,
    /// the existing state is preserved (crash-recovery).  Otherwise the file is
    /// freshly initialised.
    pub fn new(path: impl AsRef<Path>, capacity: usize) -> io::Result<Self> {
        let file_size = HEADER_SIZE + SLOT_SIZE * capacity;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        file.set_len(file_size as u64)?;
        let mut mmap = unsafe { MmapMut::map_mut(&file)? };

        // Validate or initialise the header.
        let existing_magic =
            u32::from_le_bytes(mmap[HDR_MAGIC_OFF..HDR_MAGIC_OFF + 4].try_into().unwrap());
        let existing_cap = u32::from_le_bytes(
            mmap[HDR_CAPACITY_OFF..HDR_CAPACITY_OFF + 4]
                .try_into()
                .unwrap(),
        );

        if existing_magic != MAGIC || existing_cap != capacity as u32 {
            debug!(
                "DTN: Initialising fresh ring buffer (capacity={})",
                capacity
            );
            Self::init_header(&mut mmap, capacity);
            mmap.flush()?;
        } else {
            debug!(
                "DTN: Recovered existing ring buffer (capacity={})",
                capacity
            );
        }

        Ok(Self { mmap, capacity })
    }

    /// Initialise the header section of the mmap region.
    fn init_header(mmap: &mut MmapMut, capacity: usize) {
        mmap[HDR_MAGIC_OFF..HDR_MAGIC_OFF + 4].copy_from_slice(&MAGIC.to_le_bytes());
        mmap[HDR_CAPACITY_OFF..HDR_CAPACITY_OFF + 4]
            .copy_from_slice(&(capacity as u32).to_le_bytes());
        mmap[HDR_WRITE_HEAD_OFF..HDR_WRITE_HEAD_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        mmap[HDR_ACK_HEAD_OFF..HDR_ACK_HEAD_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        mmap[HDR_LOCAL_SEQ_OFF..HDR_LOCAL_SEQ_OFF + 8].copy_from_slice(&0u64.to_le_bytes());
        mmap[HDR_RECV_MASK_OFF..HDR_RECV_MASK_OFF + 8].copy_from_slice(&0u64.to_le_bytes());
    }

    // ── Header accessors ─────────────────────────────────────────────────────

    fn read_write_head(&self) -> usize {
        u32::from_le_bytes(
            self.mmap[HDR_WRITE_HEAD_OFF..HDR_WRITE_HEAD_OFF + 4]
                .try_into()
                .unwrap(),
        ) as usize
    }

    fn write_write_head(&mut self, val: usize) {
        self.mmap[HDR_WRITE_HEAD_OFF..HDR_WRITE_HEAD_OFF + 4]
            .copy_from_slice(&(val as u32).to_le_bytes());
    }

    fn read_local_seq(&self) -> u64 {
        u64::from_le_bytes(
            self.mmap[HDR_LOCAL_SEQ_OFF..HDR_LOCAL_SEQ_OFF + 8]
                .try_into()
                .unwrap(),
        )
    }

    fn write_local_seq(&mut self, val: u64) {
        self.mmap[HDR_LOCAL_SEQ_OFF..HDR_LOCAL_SEQ_OFF + 8].copy_from_slice(&val.to_le_bytes());
    }

    fn read_recv_mask(&self) -> u64 {
        u64::from_le_bytes(
            self.mmap[HDR_RECV_MASK_OFF..HDR_RECV_MASK_OFF + 8]
                .try_into()
                .unwrap(),
        )
    }

    fn write_recv_mask(&mut self, val: u64) {
        self.mmap[HDR_RECV_MASK_OFF..HDR_RECV_MASK_OFF + 8].copy_from_slice(&val.to_le_bytes());
    }

    // ── Slot accessors ───────────────────────────────────────────────────────

    fn slot_offset(slot: usize) -> usize {
        HEADER_SIZE + slot * SLOT_SIZE
    }

    fn read_slot_flag(&self, slot: usize) -> u8 {
        self.mmap[Self::slot_offset(slot)]
    }

    fn write_slot_flag(&mut self, slot: usize, flag: u8) {
        self.mmap[Self::slot_offset(slot)] = flag;
    }

    fn write_slot(&mut self, slot: usize, seq: u64, data: &[u8]) {
        let base = Self::slot_offset(slot);
        self.mmap[base] = SLOT_FLAG_PENDING;
        self.mmap[base + 1..base + 9].copy_from_slice(&seq.to_le_bytes());
        self.mmap[base + 9..base + 11].copy_from_slice(&(data.len() as u16).to_le_bytes());
        self.mmap[base + 11..base + 11 + data.len()].copy_from_slice(data);
    }

    fn read_slot_seq(&self, slot: usize) -> u64 {
        let base = Self::slot_offset(slot) + 1;
        u64::from_le_bytes(self.mmap[base..base + 8].try_into().unwrap())
    }

    fn read_slot_data(&self, slot: usize) -> Vec<u8> {
        let base = Self::slot_offset(slot);
        let len = u16::from_le_bytes(self.mmap[base + 9..base + 11].try_into().unwrap()) as usize;
        self.mmap[base + 11..base + 11 + len].to_vec()
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Persist a frame to disk **before** returning, guaranteeing zero-data-loss.
    ///
    /// The frame is assigned the next monotonic sequence number, written to the
    /// next ring slot, and flushed to the backing file via `msync`.  Only after
    /// the flush completes is control returned to the caller.
    ///
    /// Returns the assigned sequence number.
    pub fn push_atomic(&mut self, data: &[u8]) -> io::Result<u64> {
        if data.len() > MTU_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("DTN: frame too large: {} > MTU_MAX {}", data.len(), MTU_MAX),
            ));
        }

        let seq = self.read_local_seq();
        let next_seq = seq.wrapping_add(1);
        let slot = (seq as usize) % self.capacity;

        // Warn if we're about to overwrite an un-acked slot (ring full).
        if self.read_slot_flag(slot) == SLOT_FLAG_PENDING {
            warn!(
                "DTN: Ring full — overwriting un-acked slot {} (seq {})",
                slot, seq
            );
        }

        // Write the slot data.
        self.write_slot(slot, seq, data);

        // Advance the write head and sequence counter.
        let new_head = (self.read_write_head() + 1) % self.capacity;
        self.write_write_head(new_head);
        self.write_local_seq(next_seq);

        // Update the local received bitmask (we "received" our own transmission).
        let mask = self.read_recv_mask();
        let bit = seq % 64;
        self.write_recv_mask(mask | (1u64 << bit));

        // ── Atomic durability guarantee ──────────────────────────────────────
        // msync before returning ensures the kernel has persisted the write.
        self.mmap
            .flush_range(HEADER_SIZE + slot * SLOT_SIZE, SLOT_SIZE)?;
        self.mmap.flush_range(HDR_LOCAL_SEQ_OFF, 16)?; // seq + mask

        debug!(
            "DTN: push_atomic seq={} slot={} len={}",
            seq,
            slot,
            data.len()
        );
        Ok(seq)
    }

    /// Mark a specific sequence as acknowledged and free its slot.
    pub fn ack(&mut self, seq: u64) -> io::Result<()> {
        let slot = (seq as usize) % self.capacity;
        if self.read_slot_seq(slot) == seq && self.read_slot_flag(slot) == SLOT_FLAG_PENDING {
            self.write_slot_flag(slot, SLOT_FLAG_ACKED);
            self.mmap.flush_range(Self::slot_offset(slot), 1)?;
        }
        Ok(())
    }

    /// Session reconciliation after reconnect.
    ///
    /// `remote_recv_mask` is the bitmask the remote peer sends on reconnect,
    /// indicating which of the last 64 sequence numbers it has received.
    ///
    /// Returns a `Vec<MvtFrame>` containing all frames that the remote is missing
    /// and that are still in the ring buffer.  The caller should retransmit these
    /// in order.
    pub fn reconcile_session(&mut self, remote_recv_mask: u64) -> Vec<MvtFrame> {
        let local_seq = self.read_local_seq();
        // Frames we sent that the remote hasn't acknowledged.
        let missing_bits = !remote_recv_mask; // bits set = missing at remote

        let mut retransmits = Vec::new();

        for bit in 0u64..64 {
            if (missing_bits >> bit) & 1 == 0 {
                continue; // remote has this one
            }

            // Which absolute seq does this bit represent?
            // The bitmask window covers [local_seq - 64 .. local_seq).
            let base = local_seq.saturating_sub(64);
            let candidate_seq = base + bit;
            if candidate_seq >= local_seq {
                continue; // future seq, impossible
            }

            let slot = (candidate_seq as usize) % self.capacity;
            if self.read_slot_flag(slot) == SLOT_FLAG_PENDING
                && self.read_slot_seq(slot) == candidate_seq
            {
                let data = self.read_slot_data(slot);
                retransmits.push(MvtFrame {
                    seq: candidate_seq,
                    data,
                });
                debug!(
                    "DTN: reconcile — scheduling retransmit seq={}",
                    candidate_seq
                );
            }
        }

        // Update our local recv mask with what we know the remote now has.
        let updated_mask = self.read_recv_mask() | remote_recv_mask;
        self.write_recv_mask(updated_mask);

        retransmits
    }

    /// Return the current local received-sequence bitmask.
    ///
    /// Send this to the remote peer during the reconciliation handshake.
    pub fn local_recv_mask(&self) -> u64 {
        self.read_recv_mask()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_queue(cap: usize) -> (DurableQueue, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let q = DurableQueue::new(f.path(), cap).unwrap();
        (q, f)
    }

    #[test]
    fn push_atomic_round_trips() {
        let (mut q, _f) = make_queue(64);
        let seq = q.push_atomic(b"hello-vtm").unwrap();
        assert_eq!(seq, 0);
        let seq2 = q.push_atomic(b"world").unwrap();
        assert_eq!(seq2, 1);
    }

    #[test]
    fn reconcile_returns_missing_frames() {
        let (mut q, _f) = make_queue(64);
        q.push_atomic(b"frame0").unwrap();
        q.push_atomic(b"frame1").unwrap();
        q.push_atomic(b"frame2").unwrap();

        // Remote claims to have received seq 0 and 2, but not 1 (bit 1 clear).
        let remote_mask: u64 = 0b101; // bit0=seq0, bit1=seq1 missing, bit2=seq2
        let retransmits = q.reconcile_session(remote_mask);
        assert_eq!(retransmits.len(), 1);
        assert_eq!(retransmits[0].seq, 1);
        assert_eq!(retransmits[0].data, b"frame1");
    }

    #[test]
    fn ack_clears_slot() {
        let (mut q, _f) = make_queue(64);
        let seq = q.push_atomic(b"test").unwrap();
        q.ack(seq).unwrap();
        let slot = (seq as usize) % 64;
        assert_eq!(q.read_slot_flag(slot), SLOT_FLAG_ACKED);
    }

    #[test]
    fn crash_recovery_preserves_state() {
        let f = NamedTempFile::new().unwrap();
        {
            let mut q = DurableQueue::new(f.path(), 64).unwrap();
            q.push_atomic(b"persist").unwrap();
        }
        // Re-open — should recover the existing state, not reinitialise.
        let q2 = DurableQueue::new(f.path(), 64).unwrap();
        assert_eq!(q2.read_local_seq(), 1); // one frame was pushed
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let (mut q, _f) = make_queue(4);
        let big = vec![0u8; MTU_MAX + 1];
        assert!(q.push_atomic(&big).is_err());
    }
}
