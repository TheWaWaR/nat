use futures::{
    future::{self, loop_fn, Loop},
    stream, Future, Sink, Stream,
};
use tokio::io as async_io;
// use tokio_timer::Deadline;
use bytes::Bytes;
use net2::TcpBuilder;
use std::fmt;
use std::io;
use tokio_core::{
    net::{TcpListener, TcpStream},
    reactor::Handle,
};
// use std::time::{Instant, Duration};
use bincode;
use fibers::{Executor, InPlaceExecutor, Spawn};
use igd::{tokio::search_gateway, PortMappingProtocol};
use rand;
use rustun::client::UdpClient;
use rustun::rfc5389;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use std::collections::HashSet;
use std::net::SocketAddr;

use addr::{filter_addrs, SocketAddrExt};
use error::{map_error, RendezvousError};
use util::{
    public_addr_from_stun, recover_data, sign_data, BoxFuture, RendezvousConfig, RendezvousNonce,
    SECP256K1, TcpRendezvousMsg,
};

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

/// Extension methods for `TcpListener`.
pub trait TcpListenerExt {
    /// Bind reusably to the given address. Multiple sockets can be bound to the same local address
    /// using this method.
    fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<TcpListener>;
    /// Returns all local addresses of this socket, expanding an unspecified address (eg `0.0.0.0`)
    /// into a vector of addresses, one for each network interface.
    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>>;
}

impl TcpListenerExt for TcpListener {
    fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<TcpListener> {
        let builder = TcpBuilder::bind_reusable(addr)?;
        let bind_addr = builder.local_addr()?;
        let listener = builder.listen(1024)?;
        let listener = TcpListener::from_listener(listener, &bind_addr, handle)?;
        Ok(listener)
    }

    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let addr = self.local_addr()?;
        let addrs = addr.expand_local_unspecified()?;
        Ok(addrs)
    }
}

pub trait TcpStreamExt {
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
    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        config: &RendezvousConfig,
    ) -> BoxFuture<TcpStream, RendezvousError>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static;
}

// FIXME: remove all those `unwrap()`
impl TcpStreamExt for TcpStream {
    fn connect_reusable(
        bind_addr: &SocketAddr,
        addr: &SocketAddr,
        handle: &Handle,
    ) -> BoxFuture<TcpStream, RendezvousError> {
        debug!("Binding reusable: in {:?} for {:?}", bind_addr, addr);
        let stream = TcpBuilder::bind_reusable(bind_addr)
            .unwrap()
            .to_tcp_stream()
            .unwrap();
        let the_addr = addr.clone();
        let fut = TcpStream::connect_stream(stream, addr, handle)
            .map_err(move |err| {
                debug!("connect stream error: addr={:?}, error={:?}", the_addr, err);
                err
            })
            .map_err(map_error);
        Box::new(fut) as BoxFuture<_, _>
    }

    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        config: &RendezvousConfig,
    ) -> BoxFuture<TcpStream, RendezvousError>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static,
    {
        let handle_clone = handle.clone();
        let listener = TcpListener::bind_reusable(&"0.0.0.0:0".parse().unwrap(), handle).unwrap();
        let bind_addr = listener.local_addr().unwrap();
        let our_addrs = listener.expanded_local_addrs().unwrap();
        trace!("getting rendezvous address");
        let bind_addr_v4 = match bind_addr {
            SocketAddr::V4(v) => v,
            _ => unreachable!(),
        };
        let our_privkey = config.our_privkey.clone();
        let stun_server = config.stun_server.clone();

        let fut = search_gateway(handle)
            .map_err(map_error)
            .and_then(move |gateway| {
                gateway
                    .get_any_address(PortMappingProtocol::TCP, bind_addr_v4, 300, "nat")
                    .map(|addr| Some(SocketAddr::V4(addr)))
                    .map_err(map_error)
            })
            .or_else(move |err| {
                trace!("get igd address error: {:?}", err);
                let addr = public_addr_from_stun(stun_server).get(0).cloned();
                Ok(addr)
            })
            .and_then(move |addr| {
                trace!("got rendezvous address: {:?}", addr);

                // Exchange connection info
                let our_pubkey = PublicKey::from_secret_key(&SECP256K1, &our_privkey);
                let our_nonce: RendezvousNonce = rand::random();
                let msg = TcpRendezvousMsg {
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
                        debug!("Sent rendezvous message");
                        channel
                            .map_err(|err| {
                                // FIXME: FrameTooBig Error
                                debug!("Receive rendezvous message error: {:?}", err);
                                err
                            })
                            .and_then(|msg_bytes| {
                                let msg: TcpRendezvousMsg =
                                    bincode::deserialize(&msg_bytes).unwrap();
                                debug!("Receive rendezvous message: {:?}", msg);
                                Ok(msg)
                            })
                            .into_future()
                            .map(|(item_opt, _)| item_opt.unwrap())
                            .map_err(|(err, _)| map_error(err))
                    })
                    .and_then(
                        move |TcpRendezvousMsg {
                                  pubkey,
                                  nonce,
                                  open_addrs,
                                  rendezvous_addr,
                              }| {
                            let their_addrs_set: HashSet<_> = open_addrs.into_iter().collect();
                            let our_addrs_set: HashSet<_> = our_addrs.iter().cloned().collect();
                            let mut their_addrs: HashSet<_> =
                                filter_addrs(&our_addrs_set, &their_addrs_set);
                            if let Some(rendezvous_addr) = rendezvous_addr {
                                let _ = their_addrs.insert(rendezvous_addr);
                            }
                            trace!("their_addrs == {:?}", their_addrs);

                            let their_nonce = nonce;
                            let their_pubkey = pubkey;
                            let signed_data: Vec<u8> = sign_data(&our_privkey, &their_nonce);
                            let signed_data_len = signed_data.len();

                            let connectors = their_addrs
                                .into_iter()
                                .map(|addr| {
                                    TcpStream::connect_reusable(&bind_addr, &addr, &handle_clone)
                                })
                                .collect::<Vec<_>>();
                            // FIXME: Should have deadline
                            let incoming = listener
                                .incoming()
                                .map(|(stream, _addr)| stream)
                                .map_err(map_error);

                            let tcp_streams = stream::futures_unordered(connectors)
                                .select(incoming)
                                .and_then(move |stream| {
                                    trace!(
                                        "Handshake message from {:?} to {:?}",
                                        stream.local_addr(),
                                        stream.peer_addr()
                                    );
                                    // FIXME: Should have deadline
                                    let data = signed_data.to_vec();
                                    debug!("Send data(len={}): {:?}", data.len(), data);
                                    async_io::write_all(stream, data)
                                        .and_then(|(stream, _)| async_io::flush(stream))
                                        .map_err(map_error)
                                })
                                .and_then(move |stream| {
                                    debug!("Handshake message sent");
                                    // FIXME: Should have deadline
                                    let buf = vec![0u8; signed_data_len];
                                    async_io::read_exact(stream, buf)
                                        .map_err(|err| {
                                            debug!("Read from stream error: {:?}", err);
                                            err
                                        })
                                        .map_err(map_error)
                                        .and_then(
                                            move |(stream, signed_data): (TcpStream, Vec<u8>)| {
                                                debug!(
                                                    "Receive handshake message from {:?}",
                                                    stream.peer_addr()
                                                );
                                                recover_data(&signed_data, &their_pubkey).and_then(
                                                    |nonce: RendezvousNonce| {
                                                        if nonce == our_nonce {
                                                            Ok(stream)
                                                        } else {
                                                            Err(RendezvousError::Any(format!(
                                                                "Invalid recovered nonce"
                                                            )))
                                                        }
                                                    },
                                                )
                                            },
                                        )
                                });

                            // Loop to find one valid stream
                            let fut = loop_fn(tcp_streams, |streams| {
                                streams.into_future().then(|res| {
                                    match res {
                                        Ok((stream_opt, streams)) => stream_opt
                                            .map(|stream| {
                                                let fut = future::ok(Loop::Break(stream));
                                                Box::new(fut) as BoxFuture<_, _>
                                            })
                                            .unwrap_or_else(|| {
                                                warn!("No more stream ???");
                                                let fut = future::ok(Loop::Continue(streams));
                                                Box::new(fut) as BoxFuture<_, _>
                                            }),
                                        Err((err, streams)) => {
                                            // FIXME: remove this addres from the state
                                            warn!("TCP streams error: {:?}", err);
                                            let fut = future::ok(Loop::Continue(streams));
                                            Box::new(fut) as BoxFuture<_, _>
                                        }
                                    }
                                })
                            });
                            Box::new(fut) as BoxFuture<_, _>
                        },
                    )
            });
        Box::new(fut) as BoxFuture<_, _>
    }
}
