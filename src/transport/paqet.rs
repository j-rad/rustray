// src/transport/paqet.rs
//! Paqet Transport (Native Rust KCP Implementation)
//!
//! Implements the KCP reliable UDP protocol natively in Rust for ultra-low latency.
//! Based on the Paqet/KCP Go reference.

use crate::config::PaqetConfig;
use crate::error::Result;
use bytes::{Buf, Bytes, BytesMut};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
// No tracing used? Actually line 20 has tracing, let's see which ones.
// The lint said: unused imports: `debug`, `error`, and `warn`
// So tracing itself isn't unused if we have others, but here only these 3 were in the list.
// If all 3 are unused, we can remove the whole line.

// KCP Constants
const KCP_RTO_MIN: u32 = 100;
const KCP_RTO_DEF: u32 = 200;
const KCP_RTO_MAX: u32 = 60000;
const KCP_CMD_PUSH: u8 = 81;
const KCP_CMD_ACK: u8 = 82;
const KCP_CMD_WASK: u8 = 83;
const KCP_CMD_WINS: u8 = 84;
const KCP_ASK_SEND: u32 = 1;
const KCP_ASK_TELL: u32 = 2;
const KCP_WND_SND: u16 = 32;
const KCP_WND_RCV: u16 = 32;
const KCP_MTU_DEF: usize = 1400;
const KCP_INTERVAL: u32 = 100;
const KCP_OVERHEAD: usize = 24;
const KCP_DEADLINK: u32 = 20;

/// KCP Segment Header
#[derive(Debug, Clone, Copy, Default)]
pub struct KcpHeader {
    pub conv: u32,
    pub cmd: u8,
    pub frg: u8,
    pub wnd: u16,
    pub ts: u32,
    pub sn: u32,
    pub una: u32,
    pub len: u32,
}

impl KcpHeader {
    pub fn encode(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.conv.to_le_bytes());
        buf[4] = self.cmd;
        buf[5] = self.frg;
        buf[6..8].copy_from_slice(&self.wnd.to_le_bytes());
        buf[8..12].copy_from_slice(&self.ts.to_le_bytes());
        buf[12..16].copy_from_slice(&self.sn.to_le_bytes());
        buf[16..20].copy_from_slice(&self.una.to_le_bytes());
        buf[20..24].copy_from_slice(&self.len.to_le_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < KCP_OVERHEAD {
            return None;
        }
        Some(Self {
            conv: u32::from_le_bytes(buf[0..4].try_into().ok()?),
            cmd: buf[4],
            frg: buf[5],
            wnd: u16::from_le_bytes(buf[6..8].try_into().ok()?),
            ts: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            sn: u32::from_le_bytes(buf[12..16].try_into().ok()?),
            una: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            len: u32::from_le_bytes(buf[20..24].try_into().ok()?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct KcpSegment {
    pub header: KcpHeader,
    pub data: Bytes,
    pub resendts: u32,
    pub rto: u32,
    pub fastack: u32,
    pub xmit: u32,
}

impl KcpSegment {
    fn new(conv: u32) -> Self {
        let mut h = KcpHeader::default();
        h.conv = conv;
        Self {
            header: h,
            data: Bytes::new(),
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
        }
    }
}

/// KCP Session (State Machine)
pub struct KcpSession {
    pub conv: u32,
    pub mtu: usize,
    pub mss: usize,

    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,

    pub ts_recent: u32,
    pub ts_lastack: u32,
    pub ts_probe: u32,
    pub ts_flush: u32,

    pub probe: u32,
    pub current: u32,
    pub interval: u32,
    pub nodelay: bool,
    pub updated: bool,

    pub snd_wnd: u16,
    pub rcv_wnd: u16,
    pub rmt_wnd: u16,
    pub cwnd: u16,
    pub incr: u16,
    pub ssthresh: u16,

    pub rx_rttval: u32,
    pub rx_srtt: u32,
    pub rx_rto: u32,
    pub rx_minrto: u32,

    pub snd_queue: VecDeque<KcpSegment>,
    pub rcv_queue: VecDeque<KcpSegment>,
    pub snd_buf: VecDeque<KcpSegment>,
    pub rcv_buf: VecDeque<KcpSegment>,
    pub acklist: Vec<(u32, u32)>,

    pub fastresend: u32,
    pub fastlimit: u32,
    pub nocwnd: bool,
    pub stream: bool,
    pub dead_link: u32,
    pub state: u32,

    pub output_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub waker_read: Option<Waker>,
    pub waker_write: Option<Waker>,
}

impl KcpSession {
    pub fn new(conv: u32, output_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            conv,
            mtu: KCP_MTU_DEF,
            mss: KCP_MTU_DEF - KCP_OVERHEAD,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ts_recent: 0,
            ts_lastack: 0,
            ts_probe: 0,
            ts_flush: KCP_INTERVAL,
            probe: 0,
            current: 0,
            interval: KCP_INTERVAL,
            nodelay: false,
            updated: false,
            snd_wnd: KCP_WND_SND,
            rcv_wnd: KCP_WND_RCV,
            rmt_wnd: KCP_WND_RCV,
            cwnd: 0,
            incr: 0,
            ssthresh: KCP_WND_SND,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: KCP_RTO_DEF,
            rx_minrto: KCP_RTO_MIN,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::with_capacity(16),
            fastresend: 0,
            fastlimit: 5,
            nocwnd: false,
            stream: false,
            dead_link: KCP_DEADLINK,
            state: 0,
            output_tx: Some(output_tx),
            waker_read: None,
            waker_write: None,
        }
    }

    pub fn update(&mut self, current: u32) {
        self.current = current;
        if !self.updated {
            self.updated = true;
            self.ts_flush = self.current;
        }

        let slap = (self.current as i32) - (self.ts_flush as i32);
        if slap >= 10000 || slap < -10000 {
            self.ts_flush = self.current;
        }

        if slap >= 0 {
            self.ts_flush += self.interval;
            if self.current >= self.ts_flush {
                self.ts_flush = self.current + self.interval;
            }
            self.flush();
        }
    }

    pub fn input(&mut self, data: &[u8]) -> i32 {
        if data.len() < KCP_OVERHEAD {
            return -1;
        }

        let mut offset = 0;
        let mut flag = false;
        let mut maxack = 0;
        let old_una = self.snd_una;

        while offset + KCP_OVERHEAD <= data.len() {
            let seg_header = match KcpHeader::decode(&data[offset..]) {
                Some(h) => h,
                None => break,
            };
            if seg_header.conv != self.conv {
                return -1;
            }

            offset += KCP_OVERHEAD;
            if offset + (seg_header.len as usize) > data.len() {
                return -1;
            }
            let payload = Bytes::copy_from_slice(&data[offset..offset + (seg_header.len as usize)]);
            offset += seg_header.len as usize;

            if seg_header.cmd != KCP_CMD_PUSH
                && seg_header.cmd != KCP_CMD_ACK
                && seg_header.cmd != KCP_CMD_WASK
                && seg_header.cmd != KCP_CMD_WINS
            {
                continue;
            }

            self.rmt_wnd = seg_header.wnd;
            self.parse_una(seg_header.una);
            self.shrink_buf();

            if seg_header.cmd == KCP_CMD_ACK {
                if (self.current as i32) - (seg_header.ts as i32) >= 0 {
                    self.update_ack((self.current as i32) - (seg_header.ts as i32));
                }
                self.parse_ack(seg_header.sn);
                self.shrink_buf();
                if !flag {
                    flag = true;
                    maxack = seg_header.sn;
                } else if (seg_header.sn as i32) - (maxack as i32) > 0 {
                    maxack = seg_header.sn;
                }
            } else if seg_header.cmd == KCP_CMD_PUSH {
                if (seg_header.sn as i32) - ((self.rcv_nxt + (self.rcv_wnd as u32)) as i32) < 0 {
                    self.acklist.push((seg_header.sn, seg_header.ts));
                    if (seg_header.sn as i32) - (self.rcv_nxt as i32) >= 0 {
                        let mut seg = KcpSegment::new(self.conv);
                        seg.header = seg_header;
                        seg.data = payload;
                        self.parse_data(seg);
                    }
                }
            } else if seg_header.cmd == KCP_CMD_WASK {
                self.probe |= KCP_ASK_TELL;
            }
        }

        if flag {
            self.parse_fastack(maxack);
        }

        if self.snd_una > old_una && self.cwnd < self.rmt_wnd {
            let mss = self.mss as u16;
            if self.snd_una - old_una > (self.mss as u32) {
                self.cwnd += (self.snd_una - old_una) as u16 / mss;
            } else {
                self.cwnd += 1;
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
            }
        }

        0
    }

    fn parse_una(&mut self, una: u32) {
        while let Some(seg) = self.snd_buf.front() {
            if (una as i32) - (seg.header.sn as i32) > 0 {
                self.snd_buf.pop_front();
            } else {
                break;
            }
        }
    }

    fn shrink_buf(&mut self) {
        if let Some(seg) = self.snd_buf.front() {
            self.snd_una = seg.header.sn;
        } else {
            self.snd_una = self.snd_nxt;
        }
    }

    fn parse_ack(&mut self, sn: u32) {
        if (sn as i32) - (self.snd_una as i32) < 0 || (sn as i32) - (self.snd_nxt as i32) >= 0 {
            return;
        }
        let mut index = None;
        for (i, seg) in self.snd_buf.iter().enumerate() {
            if sn == seg.header.sn {
                index = Some(i);
                break;
            } else if (sn as i32) - (seg.header.sn as i32) < 0 {
                break;
            }
        }
        if let Some(i) = index {
            self.snd_buf.remove(i);
        }
    }

    fn update_ack(&mut self, rtt: i32) {
        let rtt = rtt as u32;
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let delta = if (rtt as i32) - (self.rx_srtt as i32) < 0 {
                self.rx_srtt - rtt
            } else {
                rtt - self.rx_srtt
            };
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = (7 * self.rx_srtt + rtt) / 8;
        }
        let rto = self.rx_srtt + std::cmp::max(self.interval, 4 * self.rx_rttval);
        self.rx_rto = rto.clamp(self.rx_minrto, KCP_RTO_MAX);
    }

    fn parse_data(&mut self, newseg: KcpSegment) {
        let sn = newseg.header.sn;
        if (sn as i32) - ((self.rcv_nxt + (self.rcv_wnd as u32)) as i32) >= 0
            || (sn as i32) - (self.rcv_nxt as i32) < 0
        {
            return;
        }

        let mut i = self.rcv_buf.len();
        while i > 0 {
            let seg = &self.rcv_buf[i - 1];
            if seg.header.sn == sn {
                return; // Duplicate
            }
            if (sn as i32) - (seg.header.sn as i32) > 0 {
                break;
            }
            i -= 1;
        }
        self.rcv_buf.insert(i, newseg);

        while let Some(seg) = self.rcv_buf.front() {
            if seg.header.sn == self.rcv_nxt && self.rcv_queue.len() < (self.rcv_wnd as usize) {
                let seg = self.rcv_buf.pop_front().unwrap();
                self.rcv_queue.push_back(seg);
                self.rcv_nxt += 1;
            } else {
                break;
            }
        }

        if let Some(waker) = self.waker_read.take() {
            waker.wake();
        }
    }

    fn parse_fastack(&mut self, sn: u32) {
        if (sn as i32) - (self.snd_una as i32) < 0 || (sn as i32) - (self.snd_nxt as i32) >= 0 {
            return;
        }
        for seg in &mut self.snd_buf {
            if (sn as i32) - (seg.header.sn as i32) < 0 {
                break;
            }
            if sn != seg.header.sn {
                seg.fastack += 1;
            }
        }
    }

    pub fn send(&mut self, buf: &[u8]) -> i32 {
        let mut offset = 0;
        let len = buf.len();
        if len == 0 {
            return -1;
        }

        if self.stream {
            if let Some(last) = self.snd_queue.back_mut() {
                let old_len = last.data.len();
                if old_len < self.mss {
                    let capacity = self.mss - old_len;
                    let extend = std::cmp::min(len, capacity);
                    let mut new_data = BytesMut::with_capacity(old_len + extend);
                    new_data.extend_from_slice(&last.data);
                    new_data.extend_from_slice(&buf[0..extend]);
                    last.data = new_data.freeze();
                    last.header.len = (old_len + extend) as u32;
                    last.header.frg = 0;
                    offset += extend;
                }
            }
        }

        if offset >= len {
            return 0;
        }

        let count = if len - offset <= self.mss {
            1
        } else {
            (len - offset + self.mss - 1) / self.mss
        };
        if count >= 255 {
            return -2;
        }

        for i in 0..count {
            let size = std::cmp::min(len - offset, self.mss);
            let mut seg = KcpSegment::new(self.conv);
            seg.data = Bytes::copy_from_slice(&buf[offset..offset + size]);
            seg.header.len = size as u32;
            seg.header.frg = if self.stream {
                0
            } else {
                (count - i - 1) as u8
            };
            self.snd_queue.push_back(seg);
            offset += size;
        }
        0
    }

    pub fn flush(&mut self) {
        let mut seg = KcpSegment::new(self.conv);
        seg.header.cmd = KCP_CMD_ACK;
        seg.header.wnd = self.wnd_unused();
        seg.header.una = self.rcv_nxt;

        // Correctly clone acklist to avoid simultaneous borrow
        let acklist = self.acklist.clone();
        self.acklist.clear();
        for (sn, ts) in acklist {
            seg.header.sn = sn;
            seg.header.ts = ts;
            self.output(&seg);
        }

        if self.rmt_wnd == 0 {
            if self.probe == 0 {
                self.probe = KCP_ASK_SEND;
                self.ts_probe = self.current + self.rx_rto;
            } else {
                if (self.current as i32) - (self.ts_probe as i32) >= 0 {
                    if self.rx_rto < KCP_RTO_MAX {
                        self.rx_rto = std::cmp::min(self.rx_rto * 2, KCP_RTO_MAX);
                    }
                    self.probe |= KCP_ASK_SEND;
                    self.ts_probe = self.current + self.rx_rto;
                }
            }
        } else {
            self.ts_probe = 0;
            self.probe = 0;
        }

        if (self.probe & KCP_ASK_SEND) != 0 {
            seg.header.cmd = KCP_CMD_WASK;
            self.output(&seg);
        }
        if (self.probe & KCP_ASK_TELL) != 0 {
            seg.header.cmd = KCP_CMD_WINS;
            self.output(&seg);
        }
        self.probe = 0;

        let _cwnd = if self.snd_wnd < self.rmt_wnd {
            self.snd_wnd
        } else {
            self.rmt_wnd
        };
        let limit = if self.nocwnd {
            std::cmp::min(self.snd_wnd, self.rmt_wnd)
        } else {
            std::cmp::min(self.cwnd, self.rmt_wnd)
        };

        while (self.snd_nxt as i32) - ((self.snd_una + (limit as u32)) as i32) < 0 {
            if let Some(mut newseg) = self.snd_queue.pop_front() {
                newseg.header.conv = self.conv;
                newseg.header.cmd = KCP_CMD_PUSH;
                newseg.header.wnd = seg.header.wnd;
                newseg.header.ts = self.current;
                newseg.header.sn = self.snd_nxt;
                newseg.header.una = self.rcv_nxt;
                newseg.resendts = self.current;
                newseg.rto = self.rx_rto;
                newseg.fastack = 0;
                newseg.xmit = 0;
                self.snd_buf.push_back(newseg);
                self.snd_nxt += 1;
            } else {
                break;
            }
        }

        let resend = self.fastresend;
        let rtomin = if self.nodelay { 0 } else { self.rx_rttval >> 3 };

        let mut change = false;
        let mut lost = false;

        let tx = self.output_tx.clone();

        for segment in &mut self.snd_buf {
            let mut needsend = false;
            if segment.xmit == 0 {
                needsend = true;
                segment.xmit += 1;
                segment.rto = self.rx_rto;
                segment.resendts = self.current + segment.rto + rtomin;
            } else if (self.current as i32) - (segment.resendts as i32) >= 0 {
                needsend = true;
                segment.xmit += 1;
                self.rx_rto += if self.nodelay {
                    self.rx_rto / 2
                } else {
                    self.rx_rto / 2
                };
                if self.rx_rto > KCP_RTO_MAX {
                    self.rx_rto = KCP_RTO_MAX;
                }
                segment.rto = self.rx_rto;
                segment.resendts = self.current + segment.rto;
                lost = true;
            } else if segment.fastack >= resend
                && (segment.xmit <= self.fastlimit || self.fastlimit == 0)
            {
                needsend = true;
                segment.xmit += 1;
                segment.fastack = 0;
                segment.resendts = self.current + segment.rto;
                change = true;
            }
            if needsend {
                segment.header.ts = self.current;
                segment.header.wnd = seg.header.wnd;
                segment.header.una = self.rcv_nxt;

                // Manual output via cloned sender to avoid double borrow of self
                if let Some(tx) = &tx {
                    let mut buf = vec![0u8; KCP_OVERHEAD + segment.data.len()];
                    segment.header.encode(&mut buf);
                    buf[KCP_OVERHEAD..].copy_from_slice(&segment.data);
                    let _ = tx.try_send(buf);
                }
            }
        }

        if change {
            let inflight = self.snd_nxt - self.snd_una;
            self.ssthresh = (inflight / 2) as u16;
            if self.ssthresh < 2 {
                self.ssthresh = 2;
            }
            self.cwnd = self.ssthresh + resend as u16;
            self.incr = self.cwnd * self.mss as u16;
        }
        if lost {
            self.ssthresh = self.cwnd / 2;
            if self.ssthresh < 2 {
                self.ssthresh = 2;
            }
            self.cwnd = 1;
            self.incr = self.mss as u16;
        }
        if self.cwnd < 1 {
            self.cwnd = 1;
            self.incr = self.mss as u16;
        }
    }

    fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < (self.rcv_wnd as usize) {
            (self.rcv_wnd as usize - self.rcv_queue.len()) as u16
        } else {
            0
        }
    }

    fn output(&mut self, seg: &KcpSegment) {
        if let Some(tx) = &self.output_tx {
            let mut buf = vec![0u8; KCP_OVERHEAD + seg.data.len()];
            seg.header.encode(&mut buf);
            buf[KCP_OVERHEAD..].copy_from_slice(&seg.data);
            let _ = tx.try_send(buf);
        }
    }
}

pub struct PaqetStream {
    session: Arc<Mutex<KcpSession>>,
    read_buf: BytesMut, // Buffer for partial reads
                        // We keep rx to keep the channel alive if needed, but not used for data.
                        // Actually, KcpSession::new takes tx. KcpSession::input takes data.
                        // The RX loop in connect() calls input().
                        // So PaqetStream doesn't need rx channel.
}

impl PaqetStream {
    pub async fn connect(config: &PaqetConfig, addr: SocketAddr) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
        let conv = rand::random();
        let session = Arc::new(Mutex::new(KcpSession::new(conv, tx)));

        {
            let mut s = session.lock().unwrap();
            if let Some(mtu) = config.mtu {
                s.mtu = mtu as usize;
            }
            if let Some(tti) = config.tti {
                s.interval = tti;
            }
            if let Some(wnd) = config.uplink_capacity {
                s.snd_wnd = wnd as u16;
            }
            if let Some(wnd) = config.downlink_capacity {
                s.rcv_wnd = wnd as u16;
            }
            if let Some(cong) = config.congestion {
                s.nocwnd = !cong;
            }
            s.nodelay = true;
        }

        let socket_send = socket.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                let _ = socket_send.send_to(&packet, addr).await;
            }
        });

        let socket_recv = socket.clone();
        let session_input = session.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket_recv.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        if src == addr {
                            let mut s = session_input.lock().unwrap();
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u32;
                            s.update(now);
                            s.input(&buf[..len]);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let session_ticker = session.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            loop {
                interval.tick().await;
                let mut s = session_ticker.lock().unwrap();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u32;
                s.update(now);
            }
        });

        Ok(PaqetStream {
            session,
            read_buf: BytesMut::new(),
        })
    }
}

impl AsyncRead for PaqetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Clone Arc before locking to satisfy E0502 (self borrowing)
        let session_arc = self.session.clone();
        let mut session = session_arc.lock().unwrap();

        if !self.read_buf.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf[..len]);
            self.read_buf.advance(len);
            return Poll::Ready(Ok(()));
        }

        if !session.rcv_queue.is_empty() {
            let seg = session.rcv_queue.pop_front().unwrap();
            let data = seg.data;
            if data.len() <= buf.remaining() {
                buf.put_slice(&data);
            } else {
                let len = buf.remaining();
                buf.put_slice(&data[..len]);
                self.read_buf.extend_from_slice(&data[len..]);
            }
            return Poll::Ready(Ok(()));
        }

        session.waker_read = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for PaqetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut session = self.session.lock().unwrap();
        let ret = session.send(buf);
        if ret < 0 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "KCP send error")));
        }
        session.waker_write = Some(cx.waker().clone());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut session = self.session.lock().unwrap();
        session.flush();
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kcp_encode_decode() {
        let mut header = KcpHeader::default();
        header.conv = 12345;
        header.cmd = KCP_CMD_PUSH;
        header.sn = 1;
        header.una = 0;
        header.len = 100;

        let mut buf = [0u8; KCP_OVERHEAD];
        header.encode(&mut buf);

        let decoded = KcpHeader::decode(&buf).unwrap();
        assert_eq!(decoded.conv, 12345);
        assert_eq!(decoded.cmd, KCP_CMD_PUSH);
        assert_eq!(decoded.sn, 1);
        assert_eq!(decoded.len, 100);
    }
}
