use futures::{
    stream,
    Future,
    Stream,
    Async,
    Sink,
    IntoFuture,
    future::{
        self,
        loop_fn,
        Loop,
    },
    stream::futures_unordered::FuturesUnordered,
};
use tokio::io as async_io;
use tokio_core::{
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
    public_addr_from_stun,
};
use super::hole_punching::HolePunching;

pub trait UdpStreamExt {

    /// Bind reusably to the given address. This method can be used to create multiple UDP sockets
    /// bound to the same local address.
    fn bind_reusable(addr: &SocketAddr, handle: &Handle, remote_addr: Option<&SocketAddr>) -> io::Result<UdpSocket>;

    /// Returns a list of local addresses this socket is bind to.
    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>>;

    /// Returns a `UdpSocket` bound to the given address along with a public `SocketAddr`
    /// that can be used to message the socket from across the internet.
    fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        config: &RendezvousConfig,
    ) -> BoxFuture<(UdpSocket, SocketAddr, SocketAddr), RendezvousError>;

    /// Perform a UDP rendezvous connection to another peer. Both peers must call this
    /// simultaneously and `channel` must provide a channel through which the peers can communicate
    /// out-of-band.
    fn rendezvous_connect<C>(channel: C, handle: &Handle, config: &RendezvousConfig)
                          -> BoxFuture<(UdpSocket, SocketAddr), RendezvousError>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
    <C as Stream>::Error: fmt::Debug,
    <C as Sink>::SinkError: fmt::Debug,
        C: 'static;
}

impl UdpStreamExt for UdpSocket {

    fn bind_reusable(addr: &SocketAddr, handle: &Handle, remote_addr: Option<&SocketAddr>) -> io::Result<UdpSocket>
    {
        use std::net::IpAddr;
        let socket = match addr.ip() {
            IpAddr::V4(..) => UdpBuilder::new_v4()?,
            IpAddr::V6(..) => UdpBuilder::new_v6()?,
        };
        let _ = socket.reuse_address(true)?;

        #[cfg(target_family = "unix")]
        {
            use net2::unix::UnixUdpBuilderExt;
            let _ = socket.reuse_port(true)?;
        }
        let socket = socket.bind(addr)?;

        if let Some(remote_addr) = remote_addr {
            socket.connect(remote_addr)?;
        }

        UdpSocket::from_socket(socket, handle)
    }

    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>>
    {
        self.local_addr()?
            .expand_local_unspecified()
    }

    fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        config: &RendezvousConfig,
    ) -> BoxFuture<(UdpSocket, SocketAddr, SocketAddr), RendezvousError>
    {
        let handle = handle.clone();
        let stun_server = config.stun_server.clone();

        let bind_fut = future::result(
            UdpSocket::bind_reusable(addr, &handle, None)
                .map_err(map_error)
                .and_then(|socket| {
                    // Get local address of the socket
                    socket.local_addr()
                        .map_err(map_error)
                        .map(move |bind_addr| (socket, bind_addr))
                })
        );

        let fut = bind_fut
            .and_then(move |(socket, bind_addr)| {
                // Get public address (IpAddrExt::is_global())
                let public_addr_fut = future::result(
                    bind_addr
                        .expand_local_unspecified()
                        .map_err(map_error)
                        .and_then(move |addrs| {
                            addrs
                                .into_iter()
                                .find(|addr| IpAddrExt::is_global(&addr.ip()))
                                .ok_or_else(|| RendezvousError::Any("can not find global ip".to_string()))
                        })
                );

                public_addr_fut
                    .or_else(move |err| {
                        rendezvous_addr(&handle, bind_addr, stun_server)
                    })
                    .map(move |public_addr| (socket, bind_addr, public_addr))
            });
        Box::new(fut) as BoxFuture<_, _>
    }

    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        config: &RendezvousConfig
    ) -> BoxFuture<(UdpSocket, SocketAddr), RendezvousError>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
    <C as Stream>::Error: fmt::Debug,
    <C as Sink>::SinkError: fmt::Debug,
        C: 'static
    {
        let listen_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let our_privkey = config.our_privkey.clone();
        let stun_server = config.stun_server.clone();
        let handle0 = handle.clone();
        let fut = UdpSocket::bind_public(&listen_addr, handle, config)
            .then(move |result| match result {
                Ok((socket, bind_addr, public_addr)) => {
                    let mut our_addrs = socket.expanded_local_addrs().unwrap();
                    our_addrs.push(public_addr);
                    let our_addrs = our_addrs.into_iter().collect::<HashSet<_>>();
                    let our_pubkey = PublicKey::from_secret_key(&SECP256K1, &our_privkey);
                    let our_nonce: RendezvousNonce = rand::random();
                    let msg = UdpRendezvousMsg {
                        pubkey: our_pubkey,
                        nonce: our_nonce.clone(),
                        open_addrs: our_addrs.iter().cloned().collect(),
                        rendezvous_addrs: Vec::new(),
                    };
                    let fut = exchange_msg(channel, &msg)
                        .and_then(move |UdpRendezvousMsg{pubkey, nonce, open_addrs, rendezvous_addrs}| {
                            let their_addrs_set: HashSet<_> = open_addrs.into_iter().collect();
                            let our_addrs_set: HashSet<_> = our_addrs.iter().cloned().collect();
                            let their_open_addrs = filter_addrs(&our_addrs_set, &their_addrs_set);
                            let incoming = open_connect(
                                &handle0,
                                our_privkey.clone(),
                                our_nonce.clone(),
                                nonce.clone(),
                                pubkey.clone(),
                                socket,
                                their_open_addrs,
                                true,
                            );
                            future::ok(incoming)
                        });
                    Box::new(fut) as BoxFuture<_, _>
                }
                Err(err) => {
                    println!("public bind failed: {:?}", err);
                    let listen_socket = UdpSocket::bind_reusable(&listen_addr, &handle0, None).unwrap();
                    let handle01 = handle0.clone();
                    let hole_punching_sockets = future::loop_fn(Vec::new(), move |mut sockets| {
                        if sockets.len() == 6 {
                            return Box::new(future::ok(Loop::Break((sockets, None)))) as BoxFuture<_, _>;
                        }

                        let socket = UdpSocket::bind_reusable(&listen_addr, &handle01, None).unwrap();
                        let bind_addr = socket.local_addr().unwrap();
                        let fut = rendezvous_addr(&handle01, bind_addr, stun_server)
                            .then(move |result| match result {
                                Ok(addr) => {
                                    sockets.push((socket, addr));
                                    future::ok((Loop::Continue(sockets)))
                                }
                                Err(err) => {
                                    future::ok(Loop::Break((sockets, Some(map_error(err)))))
                                }
                            });
                        Box::new(fut) as BoxFuture<_, _>
                    });

                    let handle02 = handle0.clone();
                    let fut = hole_punching_sockets.and_then(
                        move |(sockets, err_opt): (Vec<(UdpSocket, SocketAddr)>, Option<RendezvousError>)| {
                        let (sockets, rendezvous_addrs) = sockets
                            .into_iter()
                            .unzip::<_, _, Vec<_>, _>();
                        let open_addrs = listen_socket.expanded_local_addrs().unwrap();
                        let open_addrs_set: HashSet<SocketAddr> = open_addrs.into_iter().collect();
                        let our_pubkey = PublicKey::from_secret_key(&SECP256K1, &our_privkey);
                        let our_nonce: RendezvousNonce = rand::random();
                        let msg = UdpRendezvousMsg {
                            pubkey: our_pubkey,
                            nonce: our_nonce,
                            open_addrs: open_addrs_set.clone(),
                            rendezvous_addrs,
                        };
                        exchange_msg(channel, &msg)
                            .and_then(move |their_msg| {
                                let UdpRendezvousMsg{
                                    pubkey: their_pubkey,
                                    nonce: their_nonce,
                                    open_addrs: their_open_addrs_set,
                                    rendezvous_addrs: their_rendezvous_addrs,
                                } = their_msg;
                                let mut punchers = FuturesUnordered::new();
                                for (socket, their_addr) in sockets
                                    .into_iter()
                                    .zip(their_rendezvous_addrs)
                                {
                                    let shared = SharedUdpSocket::share(socket);
                                    let with_addr = shared.with_address(their_addr);
                                    punchers.push(HolePunching::new_for_open_peer(
                                        &handle02,
                                        with_addr,
                                        our_privkey.clone(),
                                        our_nonce.clone(),
                                        their_nonce.clone(),
                                        their_pubkey.clone(),
                                    ));
                                }
                                let their_open_addrs =
                                    filter_addrs(&open_addrs_set, &their_open_addrs_set);
                                let incoming = open_connect(
                                    &handle02,
                                    our_privkey.clone(),
                                    our_nonce.clone(),
                                    their_nonce.clone(),
                                    their_pubkey.clone(),
                                    listen_socket,
                                    their_open_addrs,
                                    false,
                                ).select(punchers);
                                Box::new(future::ok(Box::new(incoming) as BoxStream<_, _>)) as BoxFuture<_, _>
                            })
                    });
                    Box::new(fut) as BoxFuture<_, _>
                }
            })
            .and_then(|incoming| select_socket(incoming));

        Box::new(fut) as BoxFuture<_, _>
    }
}

fn select_socket<S>(
    incoming: S,
) -> BoxFuture<(UdpSocket, SocketAddr), RendezvousError>
    where S: Stream<Item = (WithAddress, bool), Error = RendezvousError>,
    <S as Stream>::Error: fmt::Debug,
          S: 'static,
{
    let fut = loop_fn(incoming, |incoming| {
        incoming
            .into_future()
            .then(|res| {
                match res {
                    Ok((item_opt, incoming)) => {
                        item_opt
                            .map(|(with_addr, chosen)| {
                                let addr = with_addr.remote_addr();
                                let socket = with_addr.steal().unwrap();
                                let fut = future::ok(Loop::Break((socket, addr)));
                                Box::new(fut) as BoxFuture<_, _>
                            })
                            .unwrap_or_else(|| {
                                warn!("No more stream ???");
                                let fut = future::ok(Loop::Continue(incoming));
                                Box::new(fut) as BoxFuture<_, _>
                            })
                    }
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

fn exchange_msg<C>(
    channel: C,
    msg: &UdpRendezvousMsg,
) -> BoxFuture<UdpRendezvousMsg, RendezvousError>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
<C as Stream>::Error: fmt::Debug,
<C as Sink>::SinkError: fmt::Debug,
    C: 'static,
{
    let msg_bytes = Bytes::from(bincode::serialize(msg).unwrap());
    let fut = channel.send(msg_bytes)
        .map_err(map_error)
        .and_then(move |channel| {
            channel
                .map_err(map_error)
                .and_then(|received_bytes| {
                    let msg: UdpRendezvousMsg = bincode::deserialize(&received_bytes).unwrap();
                    debug!("Receive rendezvous message: {:?}", msg);
                    Ok(msg)
                })
                .into_future()
                .map(|(item_opt, _)| item_opt.unwrap())
                .map_err(|(err, _)| map_error(err))
        });
    Box::new(fut) as BoxFuture<_, _>
}

fn rendezvous_addr(
    handle: &Handle,
    bind_addr: SocketAddr,
    stun_server: SocketAddr,
) -> BoxFuture<SocketAddr, RendezvousError> {
    // Get public address from IGD
    let bind_addr_v4 = match bind_addr {
        SocketAddr::V4(v) => v,
        _ => unreachable!()
    };
    let fut = search_gateway(&handle)
        .map_err(map_error)
        .and_then(move |gateway| {
            gateway
                .get_any_address(PortMappingProtocol::UDP, bind_addr_v4, 300, "nat")
                .map_err(map_error)
                .map(|public_v4addr| SocketAddr::V4(public_v4addr))
        })
        .or_else(move |err| {
            // Get public address from STUN
            trace!("get igd address error: {:?}", err);
            public_addr_from_stun(stun_server)
                .get(0)
                .cloned()
                .ok_or_else(|| RendezvousError::Any("can not get public ip from STUN".to_string()))
        });
    Box::new(fut) as BoxFuture<_, _>
}

// Perform a connect where one of the peers has an open port.
fn open_connect(
    handle: &Handle,
    our_privkey: SecretKey,
    our_nonce: RendezvousNonce,
    their_nonce: RendezvousNonce,
    their_pubkey: PublicKey,
    socket: UdpSocket,
    their_addrs: HashSet<SocketAddr>,
    we_are_open: bool,
) -> BoxStream<(WithAddress, bool), RendezvousError> {
    let mut shared = SharedUdpSocket::share(socket);
    let mut punchers = FuturesUnordered::new();
    for addr in their_addrs {
        let with_addr = shared.with_address(addr);
        punchers.push(HolePunching::new_for_open_peer(
            handle,
            with_addr,
            our_privkey.clone(),
            our_nonce.clone(),
            their_nonce.clone(),
            their_pubkey.clone(),
        ));
    }

    let handle = handle.clone();
    let fut = stream::poll_fn(move || {
        trace!(
            "open_connect polling shared socket on {:?}",
            shared.local_addr()
        );

        loop {
            match shared.poll() {
                Ok(Async::Ready(Some(with_addr))) => {
                    trace!(
                        "received packet from new address {}. starting punching",
                        with_addr.remote_addr()
                    );
                    punchers.push(HolePunching::new_for_open_peer(
                        &handle,
                        with_addr,
                        our_privkey.clone(),
                        our_nonce.clone(),
                        their_nonce.clone(),
                        their_pubkey.clone(),
                    ));
                }
                Ok(Async::Ready(None)) => {
                    trace!("shared socket has been stolen");
                    break;
                }
                Ok(Async::NotReady) => {
                    trace!("nothing has arrived on the socket (yet)");
                    break;
                }
                Err(e) => {
                    error!("error reading from shared socket: {}", e);
                    break;
                }
            }
        }

        match punchers.poll()? {
            Async::Ready(Some(socket)) => {
                trace!("puncher returned success!");
                Ok(Async::Ready(Some(socket)))
            }
            Async::Ready(None) => {
                if we_are_open {
                    trace!("open_connect waiting for more connections");
                    Ok(Async::NotReady)
                } else {
                    trace!("open_connect giving up");
                    Ok(Async::Ready(None))
                }
            }
            Async::NotReady => {
                trace!("no punchers are ready yet");
                Ok(Async::NotReady)
            }
        }
    });
    Box::new(fut) as BoxStream<_, _>
}
