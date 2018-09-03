
use futures::{
    stream,
    Future,
    Stream,
    Sink,
    Async,
    AsyncSink,
    Poll,
    future::{
        self,
        loop_fn,
        Loop,
    },
};
use tokio::io as async_io;
use tokio_core::{
    self,
    reactor::Handle,
    net::{
        TcpStream,
        TcpListener,
        UdpSocket,
    },
};
use tokio_shared_udp_socket::{
    SharedUdpSocket,
    WithAddress
};
use net2::UdpBuilder;
use bytes::Bytes;
use std::io;
use std::fmt;
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use std::collections::HashSet;
use igd::{
    PortMappingProtocol,
    tokio::search_gateway,
};
use rustun::client::UdpClient;
use rustun::rfc5389;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, Signature};
use rand;
use bincode;

use error::{RendezvousError, map_error};
use addr::{SocketAddrExt, IpAddrExt, filter_addrs};
use util::{
    SECP256K1,
    BoxFuture,
    BoxStream,
    RendezvousNonce,
    UdpRendezvousMsg,
    RendezvousConfig,
    sign_data,
    recover_data,
    public_addr_from_stun,
};

/// This is the maximum possible TTL. TTL runners never exceed this TTL.
/// It could be possible to set this as high as 255, but some OSes could plausibly have restrictions
/// against setting TTLs that high. Plus, 128 is already a huge value.
const MAX_TTL: u32 = 128;

/// This is the default TTL used on Linux. Other OSes use anything from 30 to 128, but 64 is the
/// most common and the median value.
const SANE_DEFAULT_TTL: u32 = 64;

/// How many hops we expect it to take, at most, to reach the peer. The slowest TTL runner will
/// reach this value over the course of HOLE_PUNCH_DELAY_TOLERANCE.
const REALISTIC_MAX_TTL: u32 = 16;
const HOLE_PUNCH_MSG_PERIOD_MS: u64 = 200;
const HOLE_PUNCH_DELAY_TOLERANCE_SEC: u64 = 120;
const HOLE_PUNCH_INITIAL_TTL: u32 = 2;

pub struct HolePunching {
    socket: Option<WithAddress>,
    sending_msg: Option<Bytes>,
    timeout: Timeout,
    our_privkey: SecretKey,
    our_nonce: RendezvousNonce,
    their_nonce: RendezvousNonce,
    their_pubkey: PublicKey,
    phase: HolePunchingPhase,
}

enum HolePunchingPhase {
    Syn {
        time_of_last_ttl_increment: Instant,
        ttl_increment_duration: Duration,
    },
    Ack,
    AckAck {
        ack_acks_sent: u32,
        received_ack_ack: bool,
    },
}

impl HolePunching {
    pub fn new_for_open_peer(
        handle: &Handle,
        socket: WithAddress,
        our_privkey: SecretKey,
        our_nonce: RendezvousNonce,
        their_nonce: RendezvousNonce,
        their_pubkey: PublicKey,
    ) -> HolePunching {
        HolePunching {
            socket: Some(socket),
            sending_msg: None,
            timeout: Timeout::new(Duration::new(0, 0), handle),
            our_privkey,
            our_nonce,
            their_nonce,
            their_pubkey,
            phase: HolePunchingPhase::Syn {
                time_of_last_ttl_increment: Instant::now(),
                ttl_increment_duration: Duration::new(u64::max_value(), 0),
            },
        }
    }

    pub fn new_ttl_incrementer(
        handle: &Handle,
        socket: WithAddress,
        our_privkey: SecretKey,
        our_nonce: RendezvousNonce,
        their_nonce: RendezvousNonce,
        their_pubkey: PublicKey,
        duration_to_reach_max_ttl: Duration,
    ) -> HolePunching {
        HolePunching {
            socket: Some(socket),
            sending_msg: None,
            timeout: Timeout::new(Duration::new(0, 0), handle),
            our_privkey,
            our_nonce,
            their_nonce,
            their_pubkey,
            phase: HolePunchingPhase::Syn {
                time_of_last_ttl_increment: Instant::now(),
                ttl_increment_duration: {
                    duration_to_reach_max_ttl / (REALISTIC_MAX_TTL - HOLE_PUNCH_INITIAL_TTL)
                },
            },
        }
    }

    fn flush(&mut self) -> Result<Async<()>, RendezvousError> {
        loop {
            match self.socket.as_mut().unwrap().poll_complete() {
                Err(e) => return Err(RendezvousError::Any(format!("SendMessage: {:?}", e))),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(())) => (),
            };

            if let Some(bytes) = self.sending_msg.take() {
                match self.socket.as_mut().unwrap().start_send(bytes) {
                    Err(e) => return Err(RendezvousError::Any(format!("SendMessage: {:?}", e))),
                    Ok(AsyncSink::Ready) => continue,
                    Ok(AsyncSink::NotReady(bytes)) => {
                        self.sending_msg = Some(bytes);
                        return Ok(Async::NotReady);
                    }
                }
            }

            return Ok(Async::Ready(()));
        }
    }

    fn send_msg(&mut self, msg: &HolePunchMsg) -> Result<(), RendezvousError> {
        let signed_data = sign_data(&self.our_privkey, &(&self.their_nonce, msg));
        let bytes = Bytes::from(signed_data);
        debug_assert!(self.sending_msg.is_none());
        self.sending_msg = Some(bytes);
        Ok(())
    }

    fn recv_msg(&mut self) -> Result<Async<HolePunchMsg>, RendezvousError> {
        let bytes = match self.socket.as_mut().unwrap().poll() {
            Err(e) => return Err(RendezvousError::Any(format!("ReceiveMessage: {:?}", e))),
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(None)) => return Err(RendezvousError::Any(format!("SocketStolen"))),
            Ok(Async::Ready(Some(bytes))) => bytes,
        };
        let result: Result<(RendezvousNonce, HolePunchMsg), RendezvousError> =
            recover_data(&bytes, &self.their_pubkey);
        match result {
            Ok((nonce, msg)) => {
                if nonce == self.our_nonce {
                    Ok(Async::Ready(msg))
                } else {
                    Err(RendezvousError::Any(format!("Invalid recovered nonce")))
                }
            },
            Err(e) => Err(RendezvousError::Any(format!("Verify sign error: {:?}", e))),
        }
    }

    fn send_next_message(&mut self) -> Result<Async<WithAddress>, RendezvousError> {
        let hole_punch_period = Duration::from_millis(HOLE_PUNCH_MSG_PERIOD_MS);
        self.timeout.reset(Instant::now() + hole_punch_period);
        let msg = match self.phase {
            HolePunchingPhase::Syn {
                ref mut time_of_last_ttl_increment,
                ttl_increment_duration,
            } => {
                let now = Instant::now();
                while now - *time_of_last_ttl_increment > ttl_increment_duration {
                    let ttl = {
                        self.socket.as_mut()
                            .unwrap()
                            .ttl()
                            .map_err(|_| RendezvousError::Any(format!("GetTtl")))
                    }?;
                    if ttl < MAX_TTL {
                        self.socket.as_mut()
                            .unwrap()
                            .set_ttl(ttl + 1)
                            .map_err(|_| RendezvousError::Any(format!("SetTtl")))?;
                    }
                    *time_of_last_ttl_increment += ttl_increment_duration;
                }
                HolePunchMsg::Syn
            }
            HolePunchingPhase::Ack => HolePunchMsg::Ack,
            HolePunchingPhase::AckAck {
                ref mut ack_acks_sent,
                received_ack_ack,
            } => {
                if *ack_acks_sent >= 5 && received_ack_ack {
                    return Ok(Async::Ready(self.socket.take().unwrap()));
                }
                *ack_acks_sent += 1;
                HolePunchMsg::AckAck
            }
        };
        self.send_msg(&msg)?;
        Ok(Async::NotReady)
    }

    fn process_msg(&mut self, msg: &HolePunchMsg) -> Result<Async<WithAddress>, RendezvousError> {
        match *msg {
            HolePunchMsg::Syn => match self.phase {
                HolePunchingPhase::Syn { .. } => {
                    self.phase = HolePunchingPhase::Ack;
                    self.socket.as_mut()
                        .unwrap()
                        .set_ttl(SANE_DEFAULT_TTL)
                        .map_err(|_| RendezvousError::Any(format!("SetTtl")))?;
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::Ack => {
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::AckAck { .. } => (),
            },
            HolePunchMsg::Ack => match self.phase {
                HolePunchingPhase::Syn { .. } | HolePunchingPhase::Ack => {
                    self.phase = HolePunchingPhase::AckAck {
                        ack_acks_sent: 0,
                        received_ack_ack: false,
                    };
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::AckAck { .. } => {
                    self.timeout.reset(Instant::now());
                }
            },
            HolePunchMsg::AckAck => match self.phase {
                HolePunchingPhase::Syn { .. } => {
                    return Err(RendezvousError::Any(format!("UnexpectedMessage")));
                }
                HolePunchingPhase::Ack => {
                    self.phase = HolePunchingPhase::AckAck {
                        ack_acks_sent: 0,
                        received_ack_ack: true,
                    };
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::AckAck {
                    ref mut received_ack_ack,
                    ..
                } => {
                    *received_ack_ack = true;
                }
            },
            HolePunchMsg::Choose => match self.phase {
                HolePunchingPhase::Syn { .. } => {
                    return Err(RendezvousError::Any(format!("UnexpectedMessage")));
                }
                HolePunchingPhase::Ack | HolePunchingPhase::AckAck { .. } => {
                    return Ok(Async::Ready(self.socket.take().unwrap()))
                }
            },
        }
        Ok(Async::NotReady)
    }
}

impl Future for HolePunching {
    type Item = (WithAddress, bool);
    type Error = RendezvousError;

    fn poll(&mut self) -> Result<Async<(WithAddress, bool)>, RendezvousError> {
        loop {
            match self.flush()? {
                Async::NotReady => return Ok(Async::NotReady),
                Async::Ready(()) => (),
            };

            if let Async::Ready(()) = self.timeout.poll().unwrap() {
                match self.send_next_message()? {
                    Async::Ready(socket) => return Ok(Async::Ready((socket, false))),
                    Async::NotReady => continue,
                }
            }

            match self.recv_msg()? {
                Async::NotReady => return Ok(Async::NotReady),
                Async::Ready(msg) => {
                    if let Async::Ready(socket) = self.process_msg(&msg)? {
                        return Ok(Async::Ready((socket, true)));
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum HolePunchMsg {
    Syn,
    Ack,
    AckAck,
    Choose,
}

pub struct Timeout {
    inner: tokio_core::reactor::Timeout,
}

impl Timeout {
    pub fn new(duration: Duration, handle: &Handle) -> Timeout {
        Timeout {
            inner: tokio_core::reactor::Timeout::new(duration, handle).unwrap(),
        }
    }

    pub fn new_at(at: Instant, handle: &Handle) -> Timeout {
        Timeout {
            inner: tokio_core::reactor::Timeout::new_at(at, handle).unwrap(),
        }
    }

    pub fn reset(&mut self, at: Instant) {
        self.inner.reset(at)
    }
}

impl Future for Timeout {
    type Item = ();
    type Error = RendezvousError;

    fn poll(&mut self) -> Result<Async<()>, RendezvousError> {
        Ok(self.inner.poll().unwrap())
    }
}
