#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, VecDeque},
    env,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use tokio::{net::UdpSocket, signal};
use tracing::{debug, info, warn};

const MAGIC: &[u8; 8] = b"CLAVISRL";
const PROTOCOL_VERSION: u8 = 1;
const MAGIC_LEN: usize = 8;
const VERSION_OFFSET: usize = MAGIC_LEN;
const LENGTH_OFFSET: usize = VERSION_OFFSET + 1;
const SENDER_PUBKEY_HASH_OFFSET: usize = LENGTH_OFFSET + 2;
const SENDER_PUBKEY_HASH_LEN: usize = 32;
const HEADER_LEN: usize = SENDER_PUBKEY_HASH_OFFSET + SENDER_PUBKEY_HASH_LEN;
const MAX_DATAGRAM_SIZE: usize = u16::MAX as usize;

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:51820";
const PUBLIC_RELAY_EXAMPLE: &str = "relay.clavisvault.app:51820";

const RATE_LIMIT_PACKETS_PER_SECOND: u32 = 50;
const PEER_RATE_LIMIT_PACKETS_PER_SECOND: u32 = 20;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const PEER_STALE_AFTER: Duration = Duration::from_secs(5 * 60);
const PEER_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_RELAY_PAYLOAD_BYTES: usize = 2048;
const MAX_RELAY_DESTINATIONS: usize = 64;
const MAX_RELAY_PEERS: usize = 1024;
const MAX_SENDERS_PER_SOURCE_IP: usize = 128;
const SOURCE_PEER_WINDOW: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PubkeyHash([u8; 32]);

impl PubkeyHash {
    fn from_slice(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = slice
            .try_into()
            .map_err(|_| anyhow!("sender_pubkey_hash must be 32 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Debug)]
struct RelayPacket<'a> {
    sender_pubkey_hash: PubkeyHash,
    payload: &'a [u8],
}

#[derive(Debug, Clone)]
struct PeerInfo {
    addr: SocketAddr,
    last_seen: Instant,
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    packet_timestamps: VecDeque<Instant>,
}

impl RateLimitEntry {
    fn new(_now: Instant) -> Self {
        Self {
            packet_timestamps: VecDeque::new(),
        }
    }
}

#[derive(Debug)]
struct RateLimiter {
    per_ip: HashMap<IpAddr, RateLimitEntry>,
    max_packets_per_window: u32,
    window: Duration,
}

impl RateLimiter {
    fn new(max_packets_per_window: u32, window: Duration) -> Self {
        Self {
            per_ip: HashMap::new(),
            max_packets_per_window,
            window,
        }
    }

    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.cleanup_stale(now);

        let entry = self
            .per_ip
            .entry(ip)
            .or_insert_with(|| RateLimitEntry::new(now));

        let max_packets = self.max_packets_per_window as usize;

        // Keep only timestamps in the active window to enforce a strict per-second cap.
        while let Some(&oldest) = entry.packet_timestamps.front() {
            if now.duration_since(oldest) >= self.window {
                entry.packet_timestamps.pop_front();
            } else {
                break;
            }
        }

        if entry.packet_timestamps.len() >= max_packets {
            return false;
        }

        entry.packet_timestamps.push_back(now);
        true
    }

    fn cleanup_stale(&mut self, now: Instant) {
        self.per_ip.retain(|_, entry| {
            while let Some(&oldest) = entry.packet_timestamps.front() {
                if now.duration_since(oldest) >= self.window {
                    entry.packet_timestamps.pop_front();
                } else {
                    break;
                }
            }
            !entry.packet_timestamps.is_empty()
        });
    }
}

#[derive(Debug)]
struct PeerRateLimiter {
    per_peer: HashMap<PubkeyHash, RateLimitEntry>,
    max_packets_per_window: u32,
    window: Duration,
}

impl PeerRateLimiter {
    fn new(max_packets_per_window: u32, window: Duration) -> Self {
        Self {
            per_peer: HashMap::new(),
            max_packets_per_window,
            window,
        }
    }

    fn allow(&mut self, peer: PubkeyHash, now: Instant) -> bool {
        let max_packets = self.max_packets_per_window as usize;
        let entry = self
            .per_peer
            .entry(peer)
            .or_insert_with(|| RateLimitEntry::new(now));

        while let Some(&oldest) = entry.packet_timestamps.front() {
            if now.duration_since(oldest) >= self.window {
                entry.packet_timestamps.pop_front();
            } else {
                break;
            }
        }

        if entry.packet_timestamps.len() >= max_packets {
            return false;
        }

        entry.packet_timestamps.push_back(now);
        true
    }

    fn cleanup_stale(&mut self, now: Instant) {
        self.per_peer.retain(|_, entry| {
            while let Some(&oldest) = entry.packet_timestamps.front() {
                if now.duration_since(oldest) >= self.window {
                    entry.packet_timestamps.pop_front();
                } else {
                    break;
                }
            }
            !entry.packet_timestamps.is_empty()
        });
    }
}

#[derive(Debug)]
struct RelayState {
    peers: HashMap<PubkeyHash, PeerInfo>,
    limiter: RateLimiter,
    peer_limiter: PeerRateLimiter,
    source_limiter: SourceConnectionLimiter,
    last_cleanup: Instant,
}

impl RelayState {
    fn new(now: Instant) -> Self {
        Self {
            peers: HashMap::new(),
            limiter: RateLimiter::new(RATE_LIMIT_PACKETS_PER_SECOND, RATE_LIMIT_WINDOW),
            peer_limiter: PeerRateLimiter::new(
                PEER_RATE_LIMIT_PACKETS_PER_SECOND,
                RATE_LIMIT_WINDOW,
            ),
            source_limiter: SourceConnectionLimiter::new(
                MAX_SENDERS_PER_SOURCE_IP,
                SOURCE_PEER_WINDOW,
            ),
            last_cleanup: now,
        }
    }

    fn register_peer(
        &mut self,
        sender_pubkey_hash: PubkeyHash,
        addr: SocketAddr,
        now: Instant,
    ) -> bool {
        if self.peers.contains_key(&sender_pubkey_hash) {
            if let Some(peer) = self.peers.get_mut(&sender_pubkey_hash) {
                peer.addr = addr;
                peer.last_seen = now;
            }
            return true;
        }

        if self.peers.len() >= MAX_RELAY_PEERS {
            return false;
        }

        self.peers.insert(
            sender_pubkey_hash,
            PeerInfo {
                addr,
                last_seen: now,
            },
        );
        true
    }

    fn cleanup_stale_peers(&mut self, now: Instant) {
        if now.duration_since(self.last_cleanup) < PEER_CLEANUP_INTERVAL {
            return;
        }
        self.last_cleanup = now;
        self.peer_limiter.cleanup_stale(now);
        self.source_limiter.cleanup_stale(now);
        self.peers
            .retain(|_, peer| now.duration_since(peer.last_seen) <= PEER_STALE_AFTER);
    }

    fn destinations_for(&self, sender_pubkey_hash: PubkeyHash, payload: &[u8]) -> Vec<SocketAddr> {
        if let Some(target_hash) = target_hint_from_payload(payload)
            && target_hash != sender_pubkey_hash
            && let Some(target_peer) = self.peers.get(&target_hash)
        {
            return vec![target_peer.addr];
        }

        let mut destinations = self
            .peers
            .iter()
            .filter_map(|(peer_hash, peer)| {
                if *peer_hash == sender_pubkey_hash {
                    None
                } else {
                    Some(peer.addr)
                }
            })
            .collect::<Vec<_>>();
        destinations.sort_unstable();
        destinations.dedup();
        destinations
    }
}

#[derive(Debug)]
struct SourceConnectionLimiter {
    peers: HashMap<IpAddr, HashMap<PubkeyHash, Instant>>,
    max_senders_per_window: usize,
    window: Duration,
}

impl SourceConnectionLimiter {
    fn new(max_senders_per_window: usize, window: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            max_senders_per_window,
            window,
        }
    }

    fn allow(&mut self, source_ip: IpAddr, sender_hash: PubkeyHash, now: Instant) -> bool {
        let active = self.peers.entry(source_ip).or_default();

        active.retain(|_, last_seen| now.duration_since(*last_seen) < self.window);

        if active.len() >= self.max_senders_per_window && !active.contains_key(&sender_hash) {
            return false;
        }

        active.insert(sender_hash, now);
        true
    }

    fn cleanup_stale(&mut self, now: Instant) {
        self.peers.retain(|_, active| {
            active.retain(|_, last_seen| now.duration_since(*last_seen) < self.window);
            !active.is_empty()
        });
    }
}

enum Command {
    Run { bind_addr: SocketAddr },
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DatagramDecision {
    Forward(Vec<SocketAddr>),
    Drop(DatagramDropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatagramDropReason {
    SourceRateLimit,
    PeerRateLimit,
    SourcePeerLimit,
    PeerTableLimit,
    DestinationCapExceeded(usize),
    InvalidPacket,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let command = parse_args(env::args().skip(1).collect())?;
    match command {
        Command::Help => {
            print_help();
            Ok(())
        }
        Command::Run { bind_addr } => run_relay(bind_addr).await,
    }
}

fn parse_args(args: Vec<String>) -> Result<Command> {
    let mut bind_addr = DEFAULT_BIND_ADDR.to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                if i >= args.len() {
                    bail!("missing value for --bind");
                }
                bind_addr = args[i].clone();
            }
            "--help" | "-h" => return Ok(Command::Help),
            other => bail!("unknown argument: {other}"),
        }
        i += 1;
    }

    let bind_addr: SocketAddr = bind_addr
        .parse()
        .with_context(|| format!("invalid bind address: {bind_addr}"))?;
    Ok(Command::Run { bind_addr })
}

fn print_help() {
    println!("clavisvault-relay [--bind 0.0.0.0:51820]");
    println!("Custom protocol: [8]CLAVISRL [1]version [2]len [32]sender_pubkey_hash [payload]");
    println!("Public relay example: {PUBLIC_RELAY_EXAMPLE}");
}

fn parse_relay_packet(datagram: &[u8]) -> Result<RelayPacket<'_>> {
    if datagram.len() < HEADER_LEN {
        bail!("packet too short");
    }

    if &datagram[..8] != MAGIC {
        bail!("invalid magic");
    }

    let version = datagram[VERSION_OFFSET];
    if version != PROTOCOL_VERSION {
        bail!("unsupported protocol version: {version}");
    }

    let payload_len =
        u16::from_be_bytes([datagram[LENGTH_OFFSET], datagram[LENGTH_OFFSET + 1]]) as usize;
    if payload_len == 0 {
        bail!("empty relay payload");
    }
    if payload_len > MAX_RELAY_PAYLOAD_BYTES {
        bail!("relay payload exceeds size limit");
    }
    let actual_payload_len = datagram.len() - HEADER_LEN;
    if payload_len != actual_payload_len {
        bail!("declared payload len does not match datagram size");
    }

    let sender_pubkey_hash =
        PubkeyHash::from_slice(&datagram[SENDER_PUBKEY_HASH_OFFSET..HEADER_LEN])?;
    let payload = &datagram[HEADER_LEN..];

    Ok(RelayPacket {
        sender_pubkey_hash,
        payload,
    })
}

fn target_hint_from_payload(payload: &[u8]) -> Option<PubkeyHash> {
    if payload.len() < 32 {
        return None;
    }
    PubkeyHash::from_slice(&payload[..32]).ok()
}

async fn run_relay(bind_addr: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind relay socket at {bind_addr}"))?;

    let actual_addr = socket.local_addr()?;
    info!("clavisvault-relay listening on {actual_addr}");
    info!("public relay example: {PUBLIC_RELAY_EXAMPLE}");
    info!(
        "protocol active (magic=CLAVISRL version={} rate_limit={}pkt/s)",
        PROTOCOL_VERSION, RATE_LIMIT_PACKETS_PER_SECOND
    );

    let mut state = RelayState::new(Instant::now());
    let mut buffer = vec![0_u8; MAX_DATAGRAM_SIZE];

    loop {
        tokio::select! {
            recv_result = socket.recv_from(&mut buffer) => {
                let (len, src_addr) = match recv_result {
                    Ok(v) => v,
                    Err(err) => {
                        warn!("recv_from failed: {err}");
                        continue;
                    }
                };

                let now = Instant::now();
                state.cleanup_stale_peers(now);

                let datagram = &buffer[..len];
                let decision = relay_packet_decision(&mut state, src_addr, datagram, now);
                let destinations = match decision {
                    DatagramDecision::Forward(destinations) => destinations,
                    DatagramDecision::Drop(reason) => {
                    match reason {
                        DatagramDropReason::SourceRateLimit => {
                            warn!("rate-limit exceeded for {}", src_addr.ip());
                        }
                        DatagramDropReason::PeerRateLimit => {
                            warn!("peer rate-limit exceeded for sender");
                        }
                        DatagramDropReason::SourcePeerLimit => {
                            warn!("source peer limit exceeded for {}", src_addr.ip());
                        }
                        DatagramDropReason::PeerTableLimit => {
                            warn!("peer table limit reached; dropping sender {src_addr}");
                        }
                        DatagramDropReason::DestinationCapExceeded(count) => {
                            warn!(
                                "dropping packet from {src_addr} with too many destinations: {count}"
                            );
                        }
                            DatagramDropReason::InvalidPacket => {
                                debug!("dropping invalid packet from {src_addr}");
                            }
                        }
                        continue;
                    }
                };

                for destination in &destinations {
                    if *destination == src_addr {
                        continue;
                    }
                    if let Err(err) = socket.send_to(datagram, destination).await {
                        warn!("failed forwarding to {destination}: {err}");
                    }
                }
            }
            signal_result = signal::ctrl_c() => {
                signal_result?;
                info!("shutdown signal received");
                break;
            }
        }
    }

    Ok(())
}

fn relay_packet_decision(
    state: &mut RelayState,
    source: SocketAddr,
    datagram: &[u8],
    now: Instant,
) -> DatagramDecision {
    if !state.limiter.allow(source.ip(), now) {
        return DatagramDecision::Drop(DatagramDropReason::SourceRateLimit);
    }

    let packet = match parse_relay_packet(datagram) {
        Ok(packet) => packet,
        Err(_) => return DatagramDecision::Drop(DatagramDropReason::InvalidPacket),
    };

    if !state.peer_limiter.allow(packet.sender_pubkey_hash, now) {
        return DatagramDecision::Drop(DatagramDropReason::PeerRateLimit);
    }

    if !state
        .source_limiter
        .allow(source.ip(), packet.sender_pubkey_hash, now)
    {
        return DatagramDecision::Drop(DatagramDropReason::SourcePeerLimit);
    }

    if !state.register_peer(packet.sender_pubkey_hash, source, now) {
        return DatagramDecision::Drop(DatagramDropReason::PeerTableLimit);
    }
    let destinations = state.destinations_for(packet.sender_pubkey_hash, packet.payload);
    if destinations.len() > MAX_RELAY_DESTINATIONS {
        return DatagramDecision::Drop(DatagramDropReason::DestinationCapExceeded(
            destinations.len(),
        ));
    }

    DatagramDecision::Forward(destinations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash(seed: u8) -> PubkeyHash {
        PubkeyHash([seed; 32])
    }

    fn sample_hash_u16(seed: u16) -> PubkeyHash {
        let mut bytes = [0_u8; 32];
        bytes[0..2].copy_from_slice(&seed.to_le_bytes());
        PubkeyHash(bytes)
    }

    fn build_packet(sender: PubkeyHash, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
        packet.extend_from_slice(MAGIC);
        packet.push(PROTOCOL_VERSION);
        packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(&sender.0);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn parse_packet_accepts_valid_protocol_frame() {
        let sender = sample_hash(7);
        let payload = b"signal";
        let packet = build_packet(sender, payload);
        let parsed = parse_relay_packet(&packet).expect("packet should parse");
        assert_eq!(parsed.sender_pubkey_hash, sender);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_packet_rejects_wrong_magic() {
        let sender = sample_hash(2);
        let mut packet = build_packet(sender, b"x");
        packet[0] = b'X';
        assert!(parse_relay_packet(&packet).is_err());
    }

    #[test]
    fn parse_packet_rejects_too_short_header() {
        let packet = vec![0_u8; HEADER_LEN - 1];
        assert!(parse_relay_packet(&packet).is_err());
    }

    #[test]
    fn malformed_packet_is_dropped() {
        let mut state = RelayState::new(Instant::now());
        let source: SocketAddr = "127.0.0.1:5000".parse().expect("source parse");
        let datagram = vec![0_u8; 4];
        let decision = relay_packet_decision(&mut state, source, &datagram, Instant::now());
        assert!(matches!(
            decision,
            DatagramDecision::Drop(DatagramDropReason::InvalidPacket)
        ));
    }

    #[test]
    fn parse_packet_rejects_mismatched_payload_len() {
        let sender = sample_hash(4);
        let mut packet = build_packet(sender, b"hello");
        packet[9] = 0;
        packet[10] = 1;
        assert!(parse_relay_packet(&packet).is_err());
    }

    #[test]
    fn destination_fanout_cap_causes_drop() {
        let now = Instant::now();
        let sender = sample_hash(21);
        let mut state = RelayState::new(now);
        for index in 0_u8..70 {
            state.register_peer(
                sample_hash(index),
                format!("127.0.0.1:{}", 3500 + u16::from(index))
                    .parse()
                    .expect("addr"),
                now,
            );
        }

        let packet = b"compact-payload";
        let datagram = build_packet(sender, packet);
        let decision = relay_packet_decision(
            &mut state,
            "127.0.0.1:5001".parse().expect("source"),
            &datagram,
            now,
        );
        match decision {
            DatagramDecision::Drop(DatagramDropReason::DestinationCapExceeded(count)) => {
                assert_eq!(count, 69);
                assert!(count > MAX_RELAY_DESTINATIONS);
            }
            _ => panic!("expected destination cap drop"),
        }
    }

    #[test]
    fn source_peer_limit_blocks_new_hashes_per_source_ip() {
        let now = Instant::now();
        let mut state = RelayState::new(now);
        let source: SocketAddr = "127.0.0.1:6000".parse().expect("source parse");
        state.limiter.max_packets_per_window = 1000;

        for index in 0..=MAX_SENDERS_PER_SOURCE_IP {
            let sender = sample_hash_u16(u16::try_from(index).expect("index fits u16"));
            let packet = build_packet(sender, b"signal");
            let decision = relay_packet_decision(
                &mut state,
                source,
                &packet,
                now + Duration::from_millis(index as u64),
            );
            if index < MAX_SENDERS_PER_SOURCE_IP {
                assert!(
                    matches!(decision, DatagramDecision::Forward(_)),
                    "sender {index} should be accepted"
                );
            } else {
                assert!(
                    matches!(
                        decision,
                        DatagramDecision::Drop(DatagramDropReason::SourcePeerLimit)
                    ),
                    "sender {index} should be blocked by source peer limit"
                );
            }
        }
    }

    #[test]
    fn peer_table_limit_rejects_unknown_sender_when_full() {
        let now = Instant::now();
        let mut state = RelayState::new(now);
        let source: SocketAddr = "127.0.0.1:7000".parse().expect("source parse");
        state.source_limiter = SourceConnectionLimiter::new(usize::MAX, SOURCE_PEER_WINDOW);

        for index in 0..MAX_RELAY_PEERS {
            let sender = sample_hash_u16(u16::try_from(index).expect("peer index fits u16"));
            state.register_peer(
                sender,
                format!("127.0.0.1:{}", 8000 + index).parse().expect("addr"),
                now,
            );
        }

        let extra = sample_hash_u16(
            u16::try_from(MAX_RELAY_PEERS)
                .expect("max peer count must fit u16")
                .saturating_add(1),
        );
        let packet = build_packet(extra, b"signal");
        assert_eq!(
            relay_packet_decision(&mut state, source, &packet, now + Duration::from_secs(1)),
            DatagramDecision::Drop(DatagramDropReason::PeerTableLimit),
        );
    }

    #[test]
    fn parse_packet_rejects_empty_payload() {
        let sender = sample_hash(6);
        let packet = build_packet(sender, b"");
        let err = parse_relay_packet(&packet).expect_err("empty payload should be rejected");
        assert!(err.to_string().contains("empty relay payload"));
    }

    #[test]
    fn parse_packet_rejects_oversized_payload() {
        let sender = sample_hash(8);
        let payload = vec![0_u8; MAX_RELAY_PAYLOAD_BYTES + 1];
        let packet = build_packet(sender, &payload);
        let err = parse_relay_packet(&packet).expect_err("oversized payload should be rejected");
        assert!(err.to_string().contains("relay payload exceeds size limit"));
    }

    #[test]
    fn peer_rate_limiter_blocks_burst_per_peer() {
        let mut limiter = PeerRateLimiter::new(2, RATE_LIMIT_WINDOW);
        let peer = sample_hash(12);
        let now = Instant::now();

        assert!(limiter.allow(peer, now));
        assert!(limiter.allow(peer, now));
        assert!(!limiter.allow(peer, now));
        assert!(limiter.allow(peer, now + RATE_LIMIT_WINDOW));
    }

    #[test]
    fn parse_packet_rejects_unsupported_version() {
        let sender = sample_hash(5);
        let mut packet = build_packet(sender, b"v");
        packet[VERSION_OFFSET] = 99;
        assert!(parse_relay_packet(&packet).is_err());
    }

    #[test]
    fn rate_limiter_enforces_50_packets_per_second() {
        let mut limiter = RateLimiter::new(RATE_LIMIT_PACKETS_PER_SECOND, RATE_LIMIT_WINDOW);
        let ip: IpAddr = "127.0.0.1".parse().expect("ip should parse");
        let now = Instant::now();

        for _ in 0..RATE_LIMIT_PACKETS_PER_SECOND {
            assert!(limiter.allow(ip, now));
        }
        assert!(!limiter.allow(ip, now));
        assert!(limiter.allow(ip, now + RATE_LIMIT_WINDOW));
    }

    #[test]
    fn rate_limiter_rejects_burst_within_same_window() {
        let mut limiter = RateLimiter::new(RATE_LIMIT_PACKETS_PER_SECOND, RATE_LIMIT_WINDOW);
        let ip: IpAddr = "127.0.0.1".parse().expect("ip should parse");
        let now = Instant::now();

        for _ in 0..RATE_LIMIT_PACKETS_PER_SECOND {
            assert!(limiter.allow(ip, now));
        }

        assert!(!limiter.allow(ip, now + Duration::from_millis(500)));
        assert!(limiter.allow(ip, now + Duration::from_millis(1001)));
    }

    #[test]
    fn rate_limiter_is_scoped_per_source_ip() {
        let mut limiter = RateLimiter::new(2, RATE_LIMIT_WINDOW);
        let ip_a: IpAddr = "127.0.0.1".parse().expect("ip should parse");
        let ip_b: IpAddr = "127.0.0.2".parse().expect("ip should parse");
        let now = Instant::now();

        assert!(limiter.allow(ip_a, now));
        assert!(limiter.allow(ip_b, now));
        assert!(limiter.allow(ip_a, now));
        assert!(limiter.allow(ip_b, now));
        assert!(!limiter.allow(ip_a, now));
        assert!(!limiter.allow(ip_b, now));
    }

    #[test]
    fn destination_selection_prefers_target_hint() {
        let sender = sample_hash(1);
        let target = sample_hash(2);
        let other = sample_hash(3);

        let now = Instant::now();
        let mut state = RelayState::new(now);
        state.register_peer(sender, "127.0.0.1:1001".parse().expect("addr"), now);
        state.register_peer(target, "127.0.0.1:1002".parse().expect("addr"), now);
        state.register_peer(other, "127.0.0.1:1003".parse().expect("addr"), now);

        let mut payload = target.0.to_vec();
        payload.extend_from_slice(b"opaque");

        let destinations = state.destinations_for(sender, &payload);
        assert_eq!(destinations, vec!["127.0.0.1:1002".parse().expect("addr")]);
    }

    #[test]
    fn destination_selection_broadcasts_when_no_target_hint() {
        let sender = sample_hash(9);
        let peer_a = sample_hash(10);
        let peer_b = sample_hash(11);

        let now = Instant::now();
        let mut state = RelayState::new(now);
        state.register_peer(sender, "127.0.0.1:2001".parse().expect("addr"), now);
        state.register_peer(peer_a, "127.0.0.1:2002".parse().expect("addr"), now);
        state.register_peer(peer_b, "127.0.0.1:2003".parse().expect("addr"), now);

        let mut destinations = state.destinations_for(sender, b"no-target-hint");
        destinations.sort_unstable();

        let mut expected = vec![
            "127.0.0.1:2002".parse().expect("addr"),
            "127.0.0.1:2003".parse().expect("addr"),
        ];
        expected.sort_unstable();

        assert_eq!(destinations, expected);
    }

    #[test]
    fn destination_selection_caps_fanout_after_target_lookup() {
        let now = Instant::now();
        let sender = sample_hash(13);
        let mut state = RelayState::new(now);
        for i in 0_u8..70 {
            let peer = sample_hash(i);
            state.register_peer(
                peer,
                format!("127.0.0.1:{}", 3000 + u16::from(i))
                    .parse()
                    .expect("addr"),
                now,
            );
        }

        let destinations = state.destinations_for(sender, b"no-target-hint");
        assert_eq!(destinations.len(), 69);
        assert!(destinations.len() > MAX_RELAY_DESTINATIONS);
    }
}
