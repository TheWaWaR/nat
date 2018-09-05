use bincode;
use byteorder::{ByteOrder, LittleEndian};
use bytes::{BufMut, Bytes, BytesMut};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::{
    future::{self, loop_fn, Loop},
    stream, Async, AsyncSink, Future, Poll, Sink, Stream,
};
use igd::{tokio::search_gateway, PortMappingProtocol};
use net2::UdpBuilder;
use rand;
use rustun::client::UdpClient;
use rustun::rfc5389;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io as async_io;
use tokio_core::{
    self,
    net::{TcpListener, TcpStream, UdpSocket},
    reactor::Handle,
};
use tokio_shared_udp_socket::{SharedUdpSocket, WithAddress};

use addr::{filter_addrs, IpAddrExt, SocketAddrExt};
use error::{map_error, RendezvousError};
use util::{
    public_addr_from_stun, recover_data, sign_data, BoxFuture, BoxStream, RendezvousConfig,
    RendezvousNonce, SECP256K1, UdpRendezvousMsg,
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
    // Poor man's codec
    data: BytesMut,
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
            data: BytesMut::with_capacity(64 * 1024),
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
            data: BytesMut::default(),
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
        self.data.put(bytes);

        if self.data.len() >= 2 {
            let content_len = LittleEndian::read_u16(&self.data[0..2]) as usize;
            if self.data.len() >= content_len + 2 {
                let content = self.data.split_to(content_len + 2);
                let result: Result<
                    (RendezvousNonce, HolePunchMsg),
                    RendezvousError,
                > = recover_data(&content, &self.their_pubkey);
                match result {
                    Ok((nonce, msg)) => {
                        if nonce == self.our_nonce {
                            Ok(Async::Ready(msg))
                        } else {
                            Err(RendezvousError::Any(format!("Invalid recovered nonce")))
                        }
                    }
                    Err(e) => Err(RendezvousError::Any(format!("Verify sign error: {:?}", e))),
                }
            } else {
                Ok(Async::NotReady)
            }
        } else {
            Ok(Async::NotReady)
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
                        self.socket
                            .as_mut()
                            .unwrap()
                            .ttl()
                            .map_err(|_| RendezvousError::Any(format!("GetTtl")))
                    }?;
                    if ttl < MAX_TTL {
                        self.socket
                            .as_mut()
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
                    self.socket
                        .as_mut()
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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
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

pub fn choose<S>(
    incoming: S,
    our_privkey: SecretKey,
    our_pubkey: PublicKey,
    our_nonce: RendezvousNonce,
    their_pubkey: PublicKey,
    their_nonce: RendezvousNonce,
) -> BoxFuture<(UdpSocket, SocketAddr), RendezvousError>
where
    S: Stream<Item = (WithAddress, bool), Error = RendezvousError>,
    <S as Stream>::Error: fmt::Debug,
    S: 'static,
{
    let fut = loop_fn(incoming, move |incoming| {
        incoming.into_future().then(move |res| {
            match res {
                Ok((item_opt, incoming)) => match item_opt {
                    Some((with_addr, chosen)) => {
                        let we_choose = our_pubkey > their_pubkey;
                        match (we_choose, chosen) {
                            (true, true) => {
                                let fut =
                                    future::err(RendezvousError::Any(format!("UnexpectedMessage")));
                                Box::new(fut) as BoxFuture<_, _>
                            }
                            (true, false) => {
                                // send choose message, then return ok
                                let msg = HolePunchMsg::Choose;
                                let signed_data = sign_data(&our_privkey, &(&their_nonce, msg));
                                let bytes = Bytes::from(signed_data);
                                let fut =
                                    with_addr.send(bytes).map_err(map_error).map(|with_addr| {
                                        let addr = with_addr.remote_addr();
                                        let socket = with_addr.steal().unwrap();
                                        Loop::Break((socket, addr))
                                    });
                                Box::new(fut) as BoxFuture<_, _>
                            }
                            (false, true) => {
                                // been chosen, return ok
                                let addr = with_addr.remote_addr();
                                let socket = with_addr.steal().unwrap();
                                let fut = future::ok(Loop::Break((socket, addr)));
                                Box::new(fut) as BoxFuture<_, _>
                            }
                            (false, false) => {
                                // take choose message
                                let fut = take_choose(with_addr, our_nonce, their_pubkey)
                                    .map(|(socket, addr)| Loop::Break((socket, addr)));
                                Box::new(fut) as BoxFuture<_, _>
                            }
                        }
                    }
                    None => {
                        warn!("No more stream ???");
                        let fut = future::ok(Loop::Continue(incoming));
                        Box::new(fut) as BoxFuture<_, _>
                    }
                },
                Err((err, incoming)) => {
                    // FIXME: remove this addres from the state
                    warn!("UDP socket error: {:?}", err);
                    let fut = future::ok(Loop::Continue(incoming));
                    Box::new(fut) as BoxFuture<_, _>
                }
            }
        })
    });
    Box::new(fut) as BoxFuture<_, _>
}

fn take_choose(
    with_addr: WithAddress,
    our_nonce: RendezvousNonce,
    their_pubkey: PublicKey,
) -> BoxFuture<(UdpSocket, SocketAddr), RendezvousError> {
    let fut = loop_fn(
        (with_addr, BytesMut::with_capacity(64 * 1024)),
        move |(with_addr, mut data)| {
            with_addr
                .into_future()
                .map_err(|(err, _)| map_error(err))
                .and_then(move |(bytes_opt, with_addr)| {
                    if let Some(bytes) = bytes_opt {
                        data.put(bytes);
                    }

                    if data.len() >= 2 {
                        let content_len = LittleEndian::read_u16(&data[0..2]) as usize;
                        if data.len() >= content_len + 2 {
                            let content = data.split_to(content_len + 2);
                            let result: Result<
                                (RendezvousNonce, HolePunchMsg),
                                RendezvousError,
                            > = recover_data(&content, &their_pubkey);
                            match result {
                                Ok((nonce, msg)) => {
                                    if nonce == our_nonce {
                                        if msg == HolePunchMsg::Choose {
                                            let addr = with_addr.remote_addr();
                                            let socket = with_addr.steal().unwrap();
                                            let fut = future::ok(Loop::Break((socket, addr)));
                                            Box::new(fut) as BoxFuture<_, _>
                                        } else {
                                            let fut = future::ok(Loop::Continue((with_addr, data)));
                                            Box::new(fut) as BoxFuture<_, _>
                                        }
                                    } else {
                                        let fut = future::err(RendezvousError::Any(format!(
                                            "Invalid nonce"
                                        )));
                                        Box::new(fut) as BoxFuture<_, _>
                                    }
                                }
                                Err(err) => {
                                    let fut = future::err(RendezvousError::Any(format!(
                                        "Invalid signature data"
                                    )));
                                    Box::new(fut) as BoxFuture<_, _>
                                }
                            }
                        } else {
                            let fut = future::ok(Loop::Continue((with_addr, data)));
                            Box::new(fut) as BoxFuture<_, _>
                        }
                    } else {
                        let fut = future::ok(Loop::Continue((with_addr, data)));
                        Box::new(fut) as BoxFuture<_, _>
                    }
                })
        },
    );
    Box::new(fut) as BoxFuture<_, _>
}
