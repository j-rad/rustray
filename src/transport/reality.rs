// src/transport/reality.rs
use crate::app::stats::StatsManager;
use crate::config::Inbound;
use crate::config::{RealityClientConfig, RealityServerConfig};
use crate::error::Result;
use crate::router::Router;
use crate::transport::BoxedStream;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    Aes128Gcm, KeyInit,
    aead::{Aead, Payload},
};
use bytes::{Buf, BufMut, BytesMut};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

// --- Constants ---
const TLS_HEADER_LEN: usize = 5;
const RECORD_TYPE_HANDSHAKE: u8 = 22;
const RECORD_TYPE_APPLICATION_DATA: u8 = 23;

// --- CLIENT (Manual Handshake) ---
pub async fn connect(
    mut stream: BoxedStream,
    settings: &RealityClientConfig,
) -> Result<BoxedStream> {
    info!("REALITY Client: Connecting to {}", settings.server_name);

    // 1. Generate Client Keypair
    let client_static_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let client_pub_key = PublicKey::from(&client_static_secret);

    // 2. Construct ClientHello
    let client_hello = construct_client_hello(
        &settings.server_name,
        client_pub_key.as_bytes(),
        &settings.short_id,
        &settings.public_key,
    );

    // 3. Send ClientHello
    stream.write_all(&client_hello).await?;

    // 4. Receive ServerHello and other records
    let mut buf = BytesMut::new();
    let mut temp_buf = [0u8; 4096];

    // Read ServerHello (Unencrypted)
    loop {
        let n = stream.read(&mut temp_buf).await?;
        if n == 0 {
            return Err(anyhow::anyhow!("Unexpected EOF reading ServerHello"));
        }
        buf.extend_from_slice(&temp_buf[..n]);

        if buf.len() >= 5 {
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= 5 + len {
                break;
            }
        }
    }

    // Parse ServerHello
    if buf[0] != RECORD_TYPE_HANDSHAKE {
        return Err(anyhow::anyhow!("Expected Handshake record for ServerHello"));
    }
    let sh_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;

    // consume ServerHello from buf
    let sh_data = buf.split_to(5 + sh_len);

    let (server_pub_key, _server_random) = extract_handshake_params_robust(&sh_data)
        .ok_or_else(|| anyhow::anyhow!("Invalid ServerHello"))?;

    // 5. Derive Handshake Keys
    let shared_secret = client_static_secret.diffie_hellman(&PublicKey::from(server_pub_key));

    let (early_prk, _) = Hkdf::<Sha256>::extract(None, &[0u8; 0]);
    let empty_hash = Sha256::digest([]);
    let derived_early = derive_secret(&early_prk, b"derived", &empty_hash);
    let (handshake_prk, _) =
        Hkdf::<Sha256>::extract(Some(&derived_early), shared_secret.as_bytes());

    let mut transcript = Sha256::new();
    transcript.update(&client_hello[5..]);
    transcript.update(&sh_data[5..]);

    let hello_hash = transcript.clone().finalize();

    let client_hs_secret = derive_secret(&handshake_prk, b"c hs traffic", &hello_hash);
    let server_hs_secret = derive_secret(&handshake_prk, b"s hs traffic", &hello_hash);

    let (_c_hs_key, _c_hs_iv) = make_traffic_key(&client_hs_secret);
    let (s_hs_key, s_hs_iv) = make_traffic_key(&server_hs_secret);

    // 6. Decrypt subsequent records (EncryptedExtensions -> Finished)
    let s_hs_cipher = Aes128Gcm::new_from_slice(&s_hs_key).unwrap();
    let mut s_hs_seq = 0u64;

    loop {
        if buf.len() < 5 {
            let n = stream.read(&mut temp_buf).await?;
            if n == 0 {
                return Err(anyhow::anyhow!("Unexpected EOF during handshake"));
            }
            buf.extend_from_slice(&temp_buf[..n]);
            continue;
        }

        let r_type = buf[0];
        let r_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;

        if buf.len() < 5 + r_len {
            let n = stream.read(&mut temp_buf).await?;
            if n == 0 {
                return Err(anyhow::anyhow!("Unexpected EOF during handshake"));
            }
            buf.extend_from_slice(&temp_buf[..n]);
            continue;
        }

        let record_data = buf.split_to(5 + r_len);

        if r_type == 0x14 {
            // ChangeCipherSpec
            // Ignored in TLS 1.3
            continue;
        }

        if r_type == RECORD_TYPE_APPLICATION_DATA {
            let header = <&[u8; 5]>::try_from(&record_data[0..5]).unwrap();
            let encrypted = &record_data[5..];
            let decrypted = decrypt_record(encrypted, header, &s_hs_cipher, &s_hs_iv, s_hs_seq)?;
            s_hs_seq += 1;

            transcript.update(&decrypted);

            // Check if it contains Finished (Type 20)
            let mut cursor = io::Cursor::new(&decrypted);
            while cursor.remaining() >= 4 {
                let msg_type = cursor.get_u8();
                let msg_len = cursor.get_u24_be() as usize;
                if Buf::remaining(&cursor) < msg_len {
                    break;
                }

                let start_pos = cursor.position() as usize;

                if msg_type == 20 {
                    // Finished
                    let handshake_hash = transcript.clone().finalize();

                    // Derive Master Secret
                    let derived_hs = derive_secret(&handshake_prk, b"derived", &empty_hash);
                    let (master_prk, _) = Hkdf::<Sha256>::extract(Some(&derived_hs), &[0u8; 0]);

                    let client_app_secret =
                        derive_secret(&master_prk, b"c ap traffic", &handshake_hash);
                    let server_app_secret =
                        derive_secret(&master_prk, b"s ap traffic", &handshake_hash);

                    let (c_app_key, c_app_iv) = make_traffic_key(&client_app_secret);
                    let (s_app_key, s_app_iv) = make_traffic_key(&server_app_secret);

                    // Client Finished
                    let client_finished_key = derive_secret(&client_hs_secret, b"finished", &[]);
                    let mut mac =
                        <Hmac<Sha256> as KeyInit>::new_from_slice(&client_finished_key).unwrap();
                    mac.update(&handshake_hash);
                    let verify_data = mac.finalize().into_bytes();

                    let mut fin_msg = BytesMut::new();
                    fin_msg.put_u8(20);
                    fin_msg.put_u24(32);
                    fin_msg.put_slice(&verify_data);

                    let (c_hs_k, c_hs_i) = make_traffic_key(&client_hs_secret);
                    let c_hs_cipher_enc = Aes128Gcm::new_from_slice(&c_hs_k).unwrap();

                    let encrypted_fin = encrypt_record(
                        &fin_msg,
                        RECORD_TYPE_APPLICATION_DATA,
                        &c_hs_cipher_enc,
                        &c_hs_i,
                        0,
                    );

                    stream.write_all(&encrypted_fin).await?;

                    return Ok(Box::new(RealityStream::new(
                        stream,
                        Aes128Gcm::new_from_slice(&c_app_key).unwrap(),
                        c_app_iv,
                        Aes128Gcm::new_from_slice(&s_app_key).unwrap(),
                        s_app_iv,
                    )) as BoxedStream);
                }

                cursor.set_position((start_pos + msg_len) as u64);
            }
        }
    }
}

pub trait CursorExt {
    fn get_u24_be(&mut self) -> u32;
}

impl<T: AsRef<[u8]>> CursorExt for io::Cursor<T> {
    fn get_u24_be(&mut self) -> u32 {
        let mut buf = [0u8; 3];
        // Note: this panics if not enough bytes. Logic should guard.
        self.copy_to_slice(&mut buf);
        u32::from_be_bytes([0, buf[0], buf[1], buf[2]])
    }
}

fn construct_client_hello(
    server_name: &str,
    pub_key: &[u8; 32],
    short_id: &str,
    server_pub_key_hex: &str,
) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(512);

    // --- Record Header ---
    buf.put_u8(RECORD_TYPE_HANDSHAKE); // Handshake
    buf.put_u16(0x0301); // TLS 1.0 (for compatibility)
    buf.put_u16(0); // Placeholder for length

    // --- Handshake Header ---
    let ch_start = buf.len();
    buf.put_u8(1); // ClientHello
    buf.put_u24(0); // Placeholder for length

    // --- ClientHello Body ---
    buf.put_u16(0x0303); // TLS 1.2
    buf.put_slice(&generate_random()); // Random

    // Session ID (with REALITY short_id)
    let pk_bytes = hex::decode(server_pub_key_hex).unwrap_or_default();
    // Fix: Explicitly use Mac trait for new_from_slice to avoid ambiguity
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&pk_bytes)
        .unwrap_or_else(|_| <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32]).unwrap());
    mac.update(&hex::decode(short_id).unwrap_or_default());
    let session_id = mac.finalize().into_bytes();
    buf.put_u8(session_id.len() as u8);
    buf.put_slice(&session_id);

    // Cipher Suites
    buf.put_u16(2); // Length
    buf.put_u16(0x1301); // TLS_AES_128_GCM_SHA256

    // Compression Methods
    buf.put_u8(1); // Length
    buf.put_u8(0); // null

    // Extensions
    let ext_start = buf.len();
    buf.put_u16(0); // Placeholder for length

    // SNI
    let sni_ext_len = server_name.len() + 5;
    buf.put_u16(0x0000); // SNI
    buf.put_u16(sni_ext_len as u16);
    buf.put_u16((sni_ext_len - 2) as u16);
    buf.put_u8(0); // host_name
    buf.put_u16(server_name.len() as u16);
    buf.put_slice(server_name.as_bytes());

    // Key Share
    buf.put_u16(0x0033); // key_share
    buf.put_u16(38);
    buf.put_u16(36);
    buf.put_u16(0x001d); // x25519
    buf.put_u16(32);
    buf.put_slice(pub_key);

    // Update lengths
    let ext_len = buf.len() - ext_start - 2;
    buf[ext_start..ext_start + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());

    let ch_len = buf.len() - ch_start - 4;
    buf[ch_start + 1..ch_start + 4].copy_from_slice(&ch_len.to_be_bytes()[1..]);

    let rec_len = buf.len() - 5;
    buf[3..5].copy_from_slice(&(rec_len as u16).to_be_bytes());

    buf.to_vec()
}

// --- SERVER ---

pub async fn listen(
    router: Arc<Router>,
    stats: Arc<StatsManager>,
    listen_addr: &str,
    port: u16,
    inbounds: Vec<Inbound>,
) -> Result<()> {
    let addr = format!("{}:{}", listen_addr, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("REALITY: Listening on {}", addr);

    let server_config = inbounds
        .first()
        .and_then(|i| i.stream_settings.as_ref())
        .and_then(|s| s.reality_server_settings.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Missing REALITY server config"))?
        .clone();

    let fallback_dest = server_config
        .server_names
        .first()
        .cloned()
        .unwrap_or_else(|| server_config.dest.clone());

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        debug!("REALITY: Accepted connection from {}", remote_addr);

        let router = router.clone();
        let stats = stats.clone();
        let config = server_config.clone();
        let fallback = fallback_dest.clone();
        let inbounds = inbounds.clone();

        tokio::spawn(async move {
            let stream = stream;
            let mut buf = vec![0u8; 4096];
            let n = match stream.peek(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    debug!("REALITY: Peek failed: {}", e);
                    return;
                }
            };

            if n < TLS_HEADER_LEN {
                debug!("REALITY: Packet too short for TLS, forwarding to fallback");
                return forward_to_decoy(stream, &config, &fallback).await;
            }

            if buf[0] != 0x16 {
                debug!("REALITY: SpiderX detected invalid TLS header, forwarding to fallback");
                return forward_to_decoy(stream, &config, &fallback).await;
            }

            if let Some(auth_result) = check_reality_auth(&buf[..n], &config) {
                info!(
                    "REALITY: Authenticated request! User: {}",
                    auth_result.user_id
                );

                match perform_server_handshake(stream, &config, &buf[..n]).await {
                    Ok(auth_stream) => {
                        let boxed_stream: BoxedStream = Box::new(auth_stream);

                        if let Some(inbound) = inbounds.iter().find(|i| i.protocol == "vless") {
                            if let Some(crate::config::InboundSettings::Vless(vless_settings)) =
                                &inbound.settings
                                && let Err(e) = crate::protocols::vless::handle_inbound(
                                    router.clone(),
                                    stats.clone(),
                                    boxed_stream,
                                    vless_settings,
                                    remote_addr.to_string(),
                                )
                                .await
                                {
                                    warn!("VLESS handler error: {}", e);
                                }
                        } else {
                            warn!("REALITY: No VLESS inbound found to handle stream.");
                        }
                    }
                    Err(e) => {
                        error!("REALITY: Handshake failed: {}", e);
                    }
                }
            } else {
                debug!("REALITY: Auth failed. Forwarding to fallback: {}", fallback);
                forward_to_decoy(stream, &config, &fallback).await;
            }
        });
    }
}

/// Serve a decoy HTTP response using ProbeTrap, then close the connection.
///
/// The timing is drawn from empirical measurements of the real Iranian
/// services being mimicked, so a censor's RTT probe sees realistic latency.
async fn forward_to_decoy(
    mut client_stream: TcpStream,
    config: &RealityServerConfig,
    _decoy_addr: &str,
) {
    if let Some(mimic) = &config.mimic_settings {
        let _ = crate::transport::db_mimic::DbMimicServer::serve_decoy(
            &mut client_stream,
            &mimic.protocol,
        )
        .await;
        return;
    }

    // ProbeTrap is cheap to construct (just an RNG seed).
    let mut trap = crate::protocols::stealth::ProbeTrap::new();
    trap.respond(&mut client_stream).await;
}

// --- Auth Check ---

struct AuthResult {
    user_id: String,
}

fn check_reality_auth(buf: &[u8], config: &RealityServerConfig) -> Option<AuthResult> {
    let (session_id, _sni) = parse_client_hello_minimal(buf)?;

    if session_id.len() < 32 {
        return None;
    }

    for short_id_hex in &config.short_ids {
        if let Ok(short_id) = hex::decode(short_id_hex) {
            let pk_bytes = match hex::decode(&config.private_key) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&pk_bytes).ok()?;
            mac.update(&short_id);

            if mac.verify_slice(&session_id).is_ok() {
                return Some(AuthResult {
                    user_id: short_id_hex.clone(),
                });
            }
        }
    }
    None
}

// --- Handshake Implementation (Robust) ---

async fn perform_server_handshake(
    mut stream: TcpStream,
    config: &RealityServerConfig,
    peeked_buf: &[u8],
) -> Result<RealityStream> {
    if peeked_buf.len() < 5 {
        return Err(anyhow::anyhow!("Incomplete header"));
    }
    let rec_len = u16::from_be_bytes([peeked_buf[3], peeked_buf[4]]) as usize;
    let total_len = 5 + rec_len;

    let mut client_hello_full = vec![0u8; total_len];
    stream.read_exact(&mut client_hello_full).await?;

    let (_client_random, client_pub_key) = extract_handshake_params_robust(&client_hello_full)
        .ok_or_else(|| anyhow::anyhow!("Invalid ClientHello params or missing KeyShare"))?;

    let static_key_bytes =
        hex::decode(&config.private_key).map_err(|_| anyhow::anyhow!("Invalid private key hex"))?;
    if static_key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid private key length"));
    }
    let server_static_secret =
        StaticSecret::from(<[u8; 32]>::try_from(static_key_bytes.as_slice()).unwrap());
    let server_pub_key = PublicKey::from(&server_static_secret);

    let client_public = PublicKey::from(client_pub_key);
    let shared_secret = server_static_secret.diffie_hellman(&client_public);

    let (early_prk, _) = Hkdf::<Sha256>::extract(None, &[0u8; 0]);
    let empty_hash = Sha256::digest([]);
    let derived_early = derive_secret(&early_prk, b"derived", &empty_hash);

    let (handshake_prk, _) =
        Hkdf::<Sha256>::extract(Some(&derived_early), shared_secret.as_bytes());

    let mut transcript = Sha256::new();
    transcript.update(&client_hello_full[5..]);

    let server_random = generate_random();
    let server_hello = construct_server_hello(&server_random, server_pub_key.as_bytes());

    transcript.update(&server_hello[5..]);

    let hello_hash = transcript.clone().finalize();

    let client_hs_secret = derive_secret(&handshake_prk, b"c hs traffic", &hello_hash);
    let server_hs_secret = derive_secret(&handshake_prk, b"s hs traffic", &hello_hash);

    let (c_hs_key, c_hs_iv) = make_traffic_key(&client_hs_secret);
    let (s_hs_key, s_hs_iv) = make_traffic_key(&server_hs_secret);

    stream.write_all(&server_hello).await?;

    let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    stream.write_all(&ccs).await?;

    let mut server_handshake_traffic = BytesMut::new();

    let enc_ext = [0x08, 0x00, 0x00, 0x02, 0x00, 0x00];
    transcript.update(enc_ext);
    server_handshake_traffic.put_slice(&enc_ext);

    let cert_msg = [0x0b, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
    transcript.update(cert_msg);
    server_handshake_traffic.put_slice(&cert_msg);

    let cv_data = [0x0f, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
    transcript.update(cv_data);
    server_handshake_traffic.put_slice(&cv_data);

    let finished_key = derive_secret(&server_hs_secret, b"finished", &[]);
    let transcript_hash_so_far = transcript.clone().finalize();

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key).unwrap();
    mac.update(&transcript_hash_so_far);
    let verify_data = mac.finalize().into_bytes();

    let mut fin_msg = BytesMut::new();
    fin_msg.put_u8(20);
    fin_msg.put_u24(32);
    fin_msg.put_slice(&verify_data);

    transcript.update(&fin_msg);
    server_handshake_traffic.put_slice(&fin_msg);

    let s_hs_cipher = Aes128Gcm::new_from_slice(&s_hs_key).unwrap();
    let s_hs_seq = 0u64;

    let encrypted_hs = encrypt_record(
        &server_handshake_traffic,
        RECORD_TYPE_APPLICATION_DATA,
        &s_hs_cipher,
        &s_hs_iv,
        s_hs_seq,
    );

    stream.write_all(&encrypted_hs).await?;

    let derived_hs = derive_secret(&handshake_prk, b"derived", &empty_hash);
    let (master_prk, _) = Hkdf::<Sha256>::extract(Some(&derived_hs), &[0u8; 0]);

    let handshake_hash = transcript.clone().finalize();

    let client_app_secret = derive_secret(&master_prk, b"c ap traffic", &handshake_hash);
    let server_app_secret = derive_secret(&master_prk, b"s ap traffic", &handshake_hash);

    let (c_app_key, c_app_iv) = make_traffic_key(&client_app_secret);
    let (s_app_key, s_app_iv) = make_traffic_key(&server_app_secret);

    let c_hs_cipher = Aes128Gcm::new_from_slice(&c_hs_key).unwrap();
    let c_hs_seq = 0u64;

    let mut record_header = [0u8; 5];
    stream.read_exact(&mut record_header).await?;
    let r_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
    let mut enc_body = vec![0u8; r_len];
    stream.read_exact(&mut enc_body).await?;

    let decrypted = decrypt_record(&enc_body, &record_header, &c_hs_cipher, &c_hs_iv, c_hs_seq)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt Client Finished: {}", e))?;

    let client_finished_key = derive_secret(&client_hs_secret, b"finished", &[]);
    let mut cf_mac = <Hmac<Sha256> as Mac>::new_from_slice(&client_finished_key).unwrap();
    cf_mac.update(&handshake_hash);

    if decrypted.len() < 4 + 32 {
        return Err(anyhow::anyhow!("Client Finished too short"));
    }
    let client_verify_data = &decrypted[4..4 + 32];
    if cf_mac.verify_slice(client_verify_data).is_err() {
        return Err(anyhow::anyhow!("Client Finished verification failed"));
    }

    Ok(RealityStream::new(
        Box::new(stream) as BoxedStream,
        Aes128Gcm::new_from_slice(&c_app_key).unwrap(),
        c_app_iv,
        Aes128Gcm::new_from_slice(&s_app_key).unwrap(),
        s_app_iv,
    ))
}

// --- Helper Functions ---

fn derive_secret(prk: &[u8], label: &[u8], context_hash: &[u8]) -> [u8; 32] {
    hkdf_expand_label(prk, label, context_hash, 32)
}

fn hkdf_expand_label(prk: &[u8], label: &[u8], context: &[u8], len: u16) -> [u8; 32] {
    let mut info = Vec::new();
    info.put_u16(len);
    info.put_u8((6 + label.len()) as u8);
    info.put_slice(b"tls13 ");
    info.put_slice(label);
    info.put_u8(context.len() as u8);
    info.put_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(prk).unwrap();
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).unwrap();
    okm
}

fn make_traffic_key(secret: &[u8]) -> ([u8; 16], [u8; 12]) {
    let key = hkdf_expand_label(secret, b"key", &[], 16); // AES-128
    let iv = hkdf_expand_label(secret, b"iv", &[], 12);
    let mut k = [0u8; 16];
    k.copy_from_slice(&key[0..16]);
    let mut i = [0u8; 12];
    i.copy_from_slice(&iv[0..12]);
    (k, i)
}

fn encrypt_record(
    payload: &[u8],
    content_type: u8,
    cipher: &Aes128Gcm,
    iv: &[u8; 12],
    seq: u64,
) -> Vec<u8> {
    let nonce = RealityStream::compute_nonce(iv, seq);
    let mut plaintext = payload.to_vec();
    plaintext.push(content_type);

    let len = plaintext.len() + 16;
    let header = [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    out
}

fn decrypt_record(
    encrypted: &[u8],
    header: &[u8; 5],
    cipher: &Aes128Gcm,
    iv: &[u8; 12],
    seq: u64,
) -> Result<Vec<u8>> {
    let nonce = RealityStream::compute_nonce(iv, seq);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: encrypted,
                aad: header,
            },
        )
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

    let end = plaintext.len();
    if end == 0 {
        return Err(anyhow::anyhow!("Empty record"));
    }

    let mut idx = end - 1;
    while idx > 0 && plaintext[idx] == 0 {
        idx -= 1;
    }

    Ok(plaintext)
}

fn generate_random() -> [u8; 32] {
    let mut r = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut r);
    r
}

fn construct_server_hello(random: &[u8; 32], pub_key: &[u8; 32]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(200);

    buf.put_u8(RECORD_TYPE_HANDSHAKE);
    buf.put_u16(0x0303);
    buf.put_u16(0);

    let sh_start = buf.len();
    buf.put_u8(2); // ServerHello
    buf.put_u24(0);

    buf.put_u16(0x0303);
    buf.put_slice(random);
    buf.put_u8(32);
    buf.put_slice(&[0xDD; 32]); // Session ID

    buf.put_u16(0x1301); // Cipher Suite
    buf.put_u8(0);

    let ext_start = buf.len();
    buf.put_u16(0);

    buf.put_u16(0x002b); // Supported Versions
    buf.put_u16(2);
    buf.put_u16(0x0304); // TLS 1.3

    buf.put_u16(0x0033); // Key Share
    buf.put_u16(36);
    buf.put_u16(0x001d); // x25519
    buf.put_u16(32);
    buf.put_slice(pub_key);

    let ext_len = buf.len() - ext_start - 2;
    let sh_len = buf.len() - sh_start - 4;
    let rec_len = buf.len() - 5;

    let b = &mut buf[ext_start..ext_start + 2];
    b.copy_from_slice(&(ext_len as u16).to_be_bytes());

    buf[sh_start + 1] = (sh_len >> 16) as u8;
    buf[sh_start + 2] = (sh_len >> 8) as u8;
    buf[sh_start + 3] = sh_len as u8;

    let b = &mut buf[3..5];
    b.copy_from_slice(&(rec_len as u16).to_be_bytes());

    buf.to_vec()
}

fn extract_handshake_params_robust(client_hello: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let start = 5;
    if client_hello.len() < start + 6 + 32 {
        return None;
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[start + 6..start + 6 + 32]);

    let mut idx = start + 38;
    if idx >= client_hello.len() {
        return None;
    }
    let sid_len = client_hello[idx] as usize;
    idx += 1 + sid_len;

    if idx + 2 > client_hello.len() {
        return None;
    }
    let c_len = u16::from_be_bytes([client_hello[idx], client_hello[idx + 1]]) as usize;
    idx += 2 + c_len;

    if idx + 1 > client_hello.len() {
        return None;
    }
    let cm_len = client_hello[idx] as usize;
    idx += 1 + cm_len;

    if idx + 2 > client_hello.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([client_hello[idx], client_hello[idx + 1]]) as usize;
    idx += 2;

    let end_ext = idx + ext_total_len;
    if end_ext > client_hello.len() {
        return None;
    }

    while idx + 4 <= end_ext {
        let ext_type = u16::from_be_bytes([client_hello[idx], client_hello[idx + 1]]);
        let ext_len = u16::from_be_bytes([client_hello[idx + 2], client_hello[idx + 3]]) as usize;
        idx += 4;

        if ext_type == 0x0033 {
            if idx + 2 > end_ext {
                break;
            }
            let mut k_idx = idx + 2;
            let k_end = idx + ext_len;

            while k_idx + 4 < k_end {
                let group = u16::from_be_bytes([client_hello[k_idx], client_hello[k_idx + 1]]);
                let k_len =
                    u16::from_be_bytes([client_hello[k_idx + 2], client_hello[k_idx + 3]]) as usize;
                k_idx += 4;

                if group == 0x001d
                    && k_len == 32 && k_idx + 32 <= k_end {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&client_hello[k_idx..k_idx + 32]);
                        return Some((random, key));
                    }
                k_idx += k_len;
            }
        }
        idx += ext_len;
    }

    None
}

fn parse_client_hello_minimal(data: &[u8]) -> Option<(Vec<u8>, Option<String>)> {
    let mut cursor = io::Cursor::new(data);
    if Buf::remaining(&cursor) < 5 {
        return None;
    }
    cursor.advance(5);
    if Buf::remaining(&cursor) < 4 {
        return None;
    }
    cursor.advance(4);
    if Buf::remaining(&cursor) < 2 {
        return None;
    }
    cursor.advance(2);
    if Buf::remaining(&cursor) < 32 {
        return None;
    }
    cursor.advance(32);
    if Buf::remaining(&cursor) < 1 {
        return None;
    }
    let sess_id_len = cursor.get_u8() as usize;
    if Buf::remaining(&cursor) < sess_id_len {
        return None;
    }
    let mut session_id = vec![0u8; sess_id_len];
    cursor.copy_to_slice(&mut session_id);
    Some((session_id, None))
}

trait BufPutExt {
    fn put_u24(&mut self, n: u32);
}

impl BufPutExt for BytesMut {
    fn put_u24(&mut self, n: u32) {
        self.put_u8((n >> 16) as u8);
        self.put_u8((n >> 8) as u8);
        self.put_u8(n as u8);
    }
}

pub struct RealityStream {
    inner: BoxedStream,
    read_cipher: Aes128Gcm,
    read_iv: [u8; 12],
    read_seq: u64,
    write_cipher: Aes128Gcm,
    write_iv: [u8; 12],
    write_seq: u64,
    read_buf: BytesMut,
    incomplete_in: BytesMut,
    write_buf: BytesMut,
}

impl RealityStream {
    pub fn new(
        inner: BoxedStream,
        read_cipher: Aes128Gcm,
        read_iv: [u8; 12],
        write_cipher: Aes128Gcm,
        write_iv: [u8; 12],
    ) -> Self {
        Self {
            inner,
            read_cipher,
            read_iv,
            read_seq: 0,
            write_cipher,
            write_iv,
            write_seq: 0,
            read_buf: BytesMut::new(),
            incomplete_in: BytesMut::new(),
            write_buf: BytesMut::new(),
        }
    }

    fn compute_nonce(iv: &[u8; 12], seq: u64) -> GenericArray<u8, U12> {
        let mut nonce_bytes = [0u8; 12];
        let seq_bytes = seq.to_be_bytes();
        nonce_bytes.copy_from_slice(iv);
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }
        *GenericArray::from_slice(&nonce_bytes)
    }
}

impl tokio::io::AsyncRead for RealityStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let n = min(buf.remaining(), this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            let mut temp_buf = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        this.incomplete_in.is_empty();
                        return Poll::Ready(Ok(()));
                    }
                    this.incomplete_in.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            loop {
                if this.incomplete_in.len() < 5 {
                    break;
                }

                let r_len =
                    u16::from_be_bytes([this.incomplete_in[3], this.incomplete_in[4]]) as usize;

                if this.incomplete_in.len() < 5 + r_len {
                    break;
                }

                let record_data = this.incomplete_in.split_to(5 + r_len);
                let header = <&[u8; 5]>::try_from(&record_data[0..5]).unwrap();
                let encrypted = &record_data[5..];

                let decrypted = decrypt_record(
                    encrypted,
                    header,
                    &this.read_cipher,
                    &this.read_iv,
                    this.read_seq,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                this.read_seq += 1;

                if let Some((&last, content)) = decrypted.split_last() {
                    if last == 23 {
                        this.read_buf.extend_from_slice(content);
                    } else if last == 21 {
                    }
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for RealityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_buf.is_empty() {
            while !this.write_buf.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                    Poll::Ready(Ok(n)) => {
                        this.write_buf.advance(n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let to_write = min(buf.len(), 16384);
        let chunk = &buf[..to_write];

        let encrypted = encrypt_record(
            chunk,
            RECORD_TYPE_APPLICATION_DATA,
            &this.write_cipher,
            &this.write_iv,
            this.write_seq,
        );
        this.write_seq += 1;

        this.write_buf.extend_from_slice(&encrypted);

        match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
            Poll::Ready(Ok(n)) => {
                this.write_buf.advance(n);
                Poll::Ready(Ok(to_write))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(to_write)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                let this = self.get_mut();
                Pin::new(&mut this.inner).poll_shutdown(cx)
            }
            res => res,
        }
    }
}
