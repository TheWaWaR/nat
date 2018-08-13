
extern crate bytes;
#[macro_use]
extern crate log;
// #[macro_use]
// extern crate failure;
extern crate futures;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_codec;
extern crate tokio_timer;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate secp256k1;
extern crate bincode;
extern crate get_if_addrs;
extern crate net2;
extern crate igd;
extern crate rustun;
extern crate fibers;
#[macro_use]
extern crate lazy_static;
extern crate rand;


use futures::{
    stream,
    Future,
    Stream,
    Sink,
};
use tokio::io as async_io;
// use tokio_timer::Deadline;
use tokio_core::{
    reactor::Handle,
    net::{
        TcpStream,
        TcpListener,
    },
};
use net2::TcpBuilder;
use bytes::Bytes;
use std::io;
use std::fmt;
// use std::time::{Instant, Duration};
use std::net::SocketAddr;
use std::collections::HashSet;
use igd::{
    PortMappingProtocol,
    tokio::search_gateway,
};
use fibers::{Executor, InPlaceExecutor, Spawn};
use rustun::{Method, Client};
use rustun::client::UdpClient;
use rustun::rfc5389;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, Signature};

mod error;
mod addr;

use error::RendezvousError;
use addr::{SocketAddrExt, filter_addrs};

lazy_static! {
    static ref SECP256K1: Secp256k1<secp256k1::All> = Secp256k1::new();
}

type RendezvousNonce = [u8; 32];
type BoxFuture<I, E> = Box<Future<Item = I, Error = E>>;
type BoxStream<I, E> = Box<Stream<Item = I, Error = E>>;

/// Extensions methods for `TcpBuilder`.
pub trait TcpBuilderExt {
    /// Bind reusably to the given address. Multiple sockets can be bound to the same local address
    /// using this method.
    fn bind_reusable(addr: &SocketAddr) -> io::Result<TcpBuilder>;
    /// Returns all local addresses of this socket, expanding an unspecified address (eg `0.0.0.0`)
    /// into a vector of addresses, one for each network interface.
    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>>;
}

impl TcpBuilderExt for TcpBuilder {
    fn bind_reusable(addr: &SocketAddr) -> io::Result<TcpBuilder> {
        use std::net::IpAddr;
        let socket = match addr.ip() {
            IpAddr::V4(..) => TcpBuilder::new_v4()?,
            IpAddr::V6(..) => TcpBuilder::new_v6()?,
        };
        let _ = socket.reuse_address(true)?;

        #[cfg(target_family = "unix")]
        {
            use net2::unix::UnixTcpBuilderExt;
            let _ = socket.reuse_port(true)?;
        }

        let _ = socket.bind(addr)?;

        Ok(socket)
    }

    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let addr = self.local_addr()?;
        let addrs = addr.expand_local_unspecified()?;
        Ok(addrs)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RendezvousMsg {
    pubkey: PublicKey,
    /// 256bit random data
    nonce: RendezvousNonce,
    open_addrs: Vec<SocketAddr>,
    rendezvous_addr: Option<SocketAddr>,
}

// pub struct TcpRendezvousConnect {
//     inner: BoxFuture<TcpStream, RendezvousError>,
// }

// impl Future for TcpRendezvousConnect {
//     type Item = TcpStream;
//     type Error = RendezvousError;

//     fn poll(
//         &mut self,
//     ) -> Result<Async<TcpStream>, Self::Error> {
//         self.inner.poll()
//     }
// }

pub struct RendezvousConfig {
    // pub tcp_addr_querier_set: TcpAddrQuerierSet,
    // pub udp_addr_querier_set: UdpAddrQuerierSet,
    // pub igd_disabled: bool,
    // pub igd_disabled_for_rendezvous: bool,
    // pub force_use_local_port: bool,
    pub traversal_server: SocketAddr,
    pub our_privkey: SecretKey,
    pub their_pubkey: PublicKey,
}

pub trait RendezvousTcpStream {
    /// Connect to `addr` using a reusably-bound socket, bound to `bind_addr`. This can be used to
    /// create multiple TCP connections with the same local address, or with the same local address
    /// as a reusably-bound `TcpListener`.
    fn connect_reusable(
        bind_addr: &SocketAddr,
        addr: &SocketAddr,
        handle: &Handle,
    ) -> BoxFuture<TcpStream, RendezvousError>;

    /// Perform a TCP rendezvous connect. Both peers must call this method simultaneously in order
    /// to form one TCP connection, connected from both ends. `channel` must provide a channel
    /// through which the two connecting peers can communicate with each other out-of-band while
    /// negotiating the connection.
    fn rendezvous_connect<C>(channel: C, handle: &Handle, config: &RendezvousConfig)
                             -> BoxFuture<TcpStream, RendezvousError>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
    <C as Stream>::Error: fmt::Debug,
    <C as Sink>::SinkError: fmt::Debug,
        C: 'static;
}

impl RendezvousTcpStream for TcpStream {

    fn connect_reusable(
        bind_addr: &SocketAddr,
        addr: &SocketAddr,
        handle: &Handle,
    ) -> BoxFuture<TcpStream, RendezvousError> {
        let stream = TcpBuilder::bind_reusable(bind_addr)
            .unwrap()
            .to_tcp_stream()
            .unwrap();
        let fut = TcpStream::connect_stream(stream, addr, handle)
            .map_err(map_error);
        Box::new(fut) as BoxFuture<_, _>
    }

    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        config: &RendezvousConfig
    ) -> BoxFuture<TcpStream, RendezvousError>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
    <C as Stream>::Error: fmt::Debug,
    <C as Sink>::SinkError: fmt::Debug,
        C: 'static
    {
        let handle_clone = handle.clone();
        let listener = TcpListener::bind(&"0.0.0.0:0".parse().unwrap(), handle)
            .unwrap();
        let bind_addr = listener.local_addr().unwrap();
        let our_addrs = listener.local_addr()
            .unwrap()
            .expand_local_unspecified()
            .unwrap();
        trace!("getting rendezvous address");
        let bind_addr_v4 = match bind_addr {
            SocketAddr::V4(v) => v,
            _ => panic!("IPv6 not supported!")
        };
        let our_privkey = config.our_privkey.clone();
        let fut = search_gateway(handle)
            .map_err(map_error)
            .and_then(move |gateway| {
                gateway
                    .get_any_address(PortMappingProtocol::TCP, bind_addr_v4, 300, "nat")
                    .map(|addr| Some(SocketAddr::V4(addr)))
                    .map_err(map_error)
            })
            .or_else(|err| {
                // FIXME: not working now
                trace!("get igd address error: {:?}", err);
                let server = "127.0.0.1:5567".parse::<SocketAddr>().unwrap();
                let addr = public_addr_from_stun(server).get(0).cloned();
                Ok(addr)
            })
            .and_then(move |addr| {
                trace!("got rendezvous address: {:?}", addr);

                // Exchange connection info
                let our_pubkey = PublicKey::from_secret_key(&SECP256K1, &our_privkey);
                let our_nonce: RendezvousNonce = rand::random();
                let msg = RendezvousMsg {
                    pubkey: our_pubkey,
                    nonce: our_nonce.clone(),
                    open_addrs: our_addrs.iter().cloned().collect(),
                    rendezvous_addr: addr,
                };
                let msg_bytes = Bytes::from(bincode::serialize(&msg).unwrap());
                channel
                    .send(msg_bytes)
                    .map_err(map_error)
                    .and_then(move |channel| {
                        channel
                            .and_then(|msg_bytes| {
                                let msg: RendezvousMsg = bincode::deserialize(&msg_bytes).unwrap();
                                Ok(msg)
                            })
                            .into_future()
                            .map(|(item_opt, _)| item_opt.unwrap())
                            .map_err(|(err, _)| map_error(err))
                    })
                    .and_then(move |RendezvousMsg{pubkey, nonce, open_addrs, rendezvous_addr}| {
                        let their_addrs_set: HashSet<_> = open_addrs.into_iter().collect();
                        let our_addrs_set: HashSet<_> = our_addrs.iter().cloned().collect();
                        let mut their_addrs = filter_addrs(&our_addrs_set, &their_addrs_set);
                        if let Some(rendezvous_addr) = rendezvous_addr {
                            let _ = their_addrs.insert(rendezvous_addr);
                        }
                        trace!("their_addrs == {:?}", their_addrs);
                        let connectors = their_addrs
                            .into_iter()
                            .map(|addr| {
                                TcpStream::connect_reusable(&bind_addr, &addr, &handle_clone)
                            })
                            .collect::<Vec<_>>();
                        let incoming = listener
                            .incoming()
                            .map(|(stream, _addr)| stream)
                            .map_err(map_error);
                        // let incoming = Deadline::new(incoming, Instant::now() + Duration::from_secs(3));
                        let all_incoming = stream::futures_unordered(connectors)
                            .select(incoming);
                        choose_connections(
                            Box::new(all_incoming) as BoxStream<_, _>,
                            &our_privkey,
                            &our_pubkey,
                            &our_nonce,
                            &pubkey,
                            &nonce,
                        )
                    })
            });
        Box::new(fut) as BoxFuture<_, _>
    }
}


fn choose_connections(
    all_incoming: BoxStream<TcpStream, RendezvousError>,
    our_privkey: &SecretKey,
    our_pubkey: &PublicKey,
    our_nonce: &RendezvousNonce,
    their_pubkey: &PublicKey,
    their_nonce: &RendezvousNonce,
) -> BoxFuture<TcpStream, RendezvousError> {
    let signed_data: [u8; 64] = bincode::serialize(their_nonce)
        .map(|data| Message::from_slice(&data).unwrap())
        .map(|msg| SECP256K1.sign(&msg, &our_privkey))
        .map(|sign| sign.serialize_compact(&SECP256K1))
        .unwrap();

    let our_pubkey = our_pubkey.clone();
    let our_nonce = our_nonce.clone();
    let their_pubkey = their_pubkey.clone();
    let fut = all_incoming
        .and_then(move |stream| {
            trace!(
                "sending choose from {:?} to {:?}",
                stream.local_addr(),
                stream.peer_addr()
            );
            if our_pubkey > their_pubkey {
                // TODO: Should have deadline
                let fut = async_io::write_all(stream, signed_data.to_vec())
                    .and_then(|(stream, _)| async_io::flush(stream))
                    .map_err(map_error);
                Box::new(fut) as BoxFuture<_, _>
            } else {
                // TODO: Should have deadline
                let buf = vec![0u8; 64];
                let fut = async_io::read_exact(stream, buf)
                    .map_err(map_error)
                    .and_then(move |(stream, signed_data): (TcpStream, Vec<u8>)| {
                        Signature::from_compact(&SECP256K1, &signed_data)
                            .map_err(map_error)
                            .and_then(move |sign| {
                                let data = bincode::serialize(&our_nonce).unwrap();
                                let msg = Message::from_slice(&data).unwrap();
                                SECP256K1.verify(&msg, &sign, &their_pubkey)
                                    .map_err(map_error)
                            })
                            .map(|_| stream)
                    });
                Box::new(fut) as BoxFuture<_, _>
            }
        })
        .then(|v: Result<TcpStream, RendezvousError>| v)
        .into_future()
        .map(|(stream_opt, _)| stream_opt.unwrap())
        .map_err(|(err, _)| err);
    Box::new(fut) as BoxFuture<_, _>
}

fn public_addr_from_stun(server: SocketAddr) -> Vec<SocketAddr> {
    let mut executor = InPlaceExecutor::new().unwrap();
    let mut client = UdpClient::new(&executor.handle(), server);
    let request = rfc5389::methods::Binding.request::<rfc5389::Attribute>();
    let monitor = executor.spawn_monitor(client.call(request));
    match executor.run_fiber(monitor).unwrap().unwrap() {
        Ok(resp) => {
            debug!("OK: {:?}", resp);
            resp
                .attributes()
                .into_iter()
                .filter_map(|attr| {
                    match attr {
                        rfc5389::Attribute::XorMappedAddress(addr) => {
                            Some(addr.address())
                        }
                        _ => None
                    }
                })
                .collect::<Vec<SocketAddr>>()
        },
        Err(e) => {
            debug!("ERROR: {:?}", e);
            Vec::new()
        },
    }
}

fn map_error<E: fmt::Debug>(e: E) -> RendezvousError {
    RendezvousError::Any(format!("{:?}", e))
}

// pub fn rendezvous_addr(
// )
//     -> Box<Future<SocketAddr, RendezvousError>>
// {
// }
