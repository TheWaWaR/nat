use std::io;
use std::collections::HashSet;
use std::net::{
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6,
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};
use get_if_addrs::{self, IfAddr};

/// Some helpful additional methods for `SocketAddr`.
pub trait SocketAddrExt {
    /// If the IP address is an unspecified address (eg. `0.0.0.0`), then it is expanded into a
    /// vector with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddr>>;

    /// If this is the unspecified address then map it to the localhost address.
    fn unspecified_to_localhost(&self) -> SocketAddr;
}

impl SocketAddrExt for SocketAddr {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddr>> {
        let ret = match *self {
            SocketAddr::V4(v4_addr) => v4_addr
                .expand_local_unspecified()?
                .into_iter()
                .map(SocketAddr::V4)
                .collect(),
            SocketAddr::V6(v6_addr) => v6_addr
                .expand_local_unspecified()?
                .into_iter()
                .map(SocketAddr::V6)
                .collect(),
        };
        Ok(ret)
    }

    fn unspecified_to_localhost(&self) -> SocketAddr {
        SocketAddr::new(self.ip().unspecified_to_localhost(), self.port())
    }
}

/// Some helpful additional methods for `SocketAddrV4`.
pub trait SocketAddrV4Ext {
    /// If the IP address is the unspecified address `0.0.0.0`, then it is expanded into a vector
    /// with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV4>>;

    /// Convert the unspecified address 0.0.0.0 to 127.0.0.1
    fn unspecified_to_localhost(&self) -> SocketAddrV4;
}

/// Some helpful additional methods for `SocketAddrV6`.
pub trait SocketAddrV6Ext {
    /// If the IP address is the unspecified address `::`, then it is expanded into a vector with a
    /// seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV6>>;

    /// Convert the unspecified address :: to ::1
    fn unspecified_to_localhost(&self) -> SocketAddrV6;
}

impl SocketAddrV4Ext for SocketAddrV4 {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV4>> {
        Ok({
            self.ip()
                .expand_local_unspecified()?
                .into_iter()
                .map(|ip| SocketAddrV4::new(ip, self.port()))
                .collect()
        })
    }

    fn unspecified_to_localhost(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip().unspecified_to_localhost(), self.port())
    }
}

impl SocketAddrV6Ext for SocketAddrV6 {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV6>> {
        Ok({
            self.ip()
                .expand_local_unspecified()?
                .into_iter()
                .map(|ip| SocketAddrV6::new(ip, self.port(), self.flowinfo(), self.scope_id()))
                .collect()
        })
    }

    fn unspecified_to_localhost(&self) -> SocketAddrV6 {
        SocketAddrV6::new(
            self.ip().unspecified_to_localhost(),
            self.port(),
            self.flowinfo(),
            self.scope_id(),
        )
    }
}

/// Some helpful additional methods for `IpvAddr`.
pub trait IpAddrExt {
    /// Check whether an IP address is global.
    fn is_global(&self) -> bool;

    /// Check whether an IP address belongs to a private subnet.
    fn is_private(&self) -> bool;

    /// If the IP address is an unspecified address (eg. `0.0.0.0`), then it is expanded into a
    /// vector with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<IpAddr>>;

    /// If this is the unspecified address then map it to the localhost address.
    fn unspecified_to_localhost(&self) -> IpAddr;
}

impl IpAddrExt for IpAddr {
    fn is_global(&self) -> bool {
        match *self {
            IpAddr::V4(ref ip) => Ipv4AddrExt::is_global(ip),
            IpAddr::V6(ref ip) => Ipv6AddrExt::is_global(ip),
        }
    }

    fn is_private(&self) -> bool {
        match *self {
            //IpAddr::V4(ref ip) => Ipv4AddrExt::is_private(ip),
            IpAddr::V4(ref ip) => ip.is_private(),
            IpAddr::V6(_) => false,
        }
    }

    fn expand_local_unspecified(&self) -> io::Result<Vec<IpAddr>> {
        let ret = match *self {
            IpAddr::V4(v4_addr) => v4_addr
                .expand_local_unspecified()?
                .into_iter()
                .map(IpAddr::V4)
                .collect(),
            IpAddr::V6(v6_addr) => v6_addr
                .expand_local_unspecified()?
                .into_iter()
                .map(IpAddr::V6)
                .collect(),
        };
        Ok(ret)
    }

    fn unspecified_to_localhost(&self) -> IpAddr {
        match *self {
            IpAddr::V4(ref ip) => IpAddr::V4(ip.unspecified_to_localhost()),
            IpAddr::V6(ref ip) => IpAddr::V6(ip.unspecified_to_localhost()),
        }
    }
}

/// Some helpful additional methods for `Ipv4Addr`.
pub trait Ipv4AddrExt {
    /// Check whether an IP address is global.
    fn is_global(&self) -> bool;

    /// If the IP address is the unspecified address `0.0.0.0`, then it is expanded into a vector
    /// with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv4Addr>>;

    /// Convert the unspecified address 0.0.0.0 to 127.0.0.1
    fn unspecified_to_localhost(&self) -> Ipv4Addr;
}

/// Some helpful additional methods for `Ipv6Addr`.
pub trait Ipv6AddrExt {
    /// Check whether an IP address is global.
    fn is_global(&self) -> bool;

    /// If the IP address is the unspecified address `::`, then it is expanded into a vector with a
    /// seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv6Addr>>;

    /// Convert the unspecified address :: to ::1
    fn unspecified_to_localhost(&self) -> Ipv6Addr;
}

impl Ipv4AddrExt for Ipv4Addr {
    fn is_global(&self) -> bool {
        !self.is_private()
            && !self.is_loopback()
            && !self.is_link_local()
            && !self.is_broadcast()
            && !self.is_documentation()
            && !self.is_unspecified()
    }

    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv4Addr>> {
        if !self.is_unspecified() {
            return Ok(vec![*self]);
        }

        let mut ret = Vec::new();
        let ifs = get_if_addrs::get_if_addrs()?;
        for interface in ifs {
            if let IfAddr::V4(v4_addr) = interface.addr {
                ret.push(v4_addr.ip);
            }
        }
        Ok(ret)
    }

    fn unspecified_to_localhost(&self) -> Ipv4Addr {
        if self.is_unspecified() {
            "127.0.0.1".parse().unwrap()
        } else {
            *self
        }
    }
}

impl Ipv6AddrExt for Ipv6Addr {
    fn is_global(&self) -> bool {
        // TODO: this is very incomplete
        !self.is_loopback() && !self.is_unspecified()
    }

    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv6Addr>> {
        if !self.is_unspecified() {
            return Ok(vec![*self]);
        }

        let mut ret = Vec::new();
        let ifs = get_if_addrs::get_if_addrs()?;
        for interface in ifs {
            if let IfAddr::V6(v6_addr) = interface.addr {
                ret.push(v6_addr.ip);
            }
        }
        Ok(ret)
    }

    fn unspecified_to_localhost(&self) -> Ipv6Addr {
        if self.is_unspecified() {
            "::1".parse().unwrap()
        } else {
            *self
        }
    }
}

pub fn filter_addrs(
    our_addrs: &HashSet<SocketAddr>,
    their_addrs: &HashSet<SocketAddr>,
) -> HashSet<SocketAddr> {
    let our_global_addrs = {
        our_addrs
            .iter()
            .cloned()
            .filter(|addr| IpAddrExt::is_global(&addr.ip()))
            .collect::<HashSet<_>>()
    };
    let our_private_addrs = {
        our_addrs
            .iter()
            .cloned()
            .filter(|addr| addr.ip().is_private())
            .collect::<HashSet<_>>()
    };
    let their_global_addrs = {
        their_addrs
            .iter()
            .cloned()
            .filter(|addr| IpAddrExt::is_global(&addr.ip()))
            .collect::<HashSet<_>>()
    };
    let any_global_ips_in_common = {
        their_global_addrs
            .iter()
            .any(|a0| our_global_addrs.iter().any(|a1| a0.ip() == a1.ip()))
    };
    let maybe_same_subnet =
        any_global_ips_in_common || (their_global_addrs.is_empty() && our_global_addrs.is_empty());
    let their_filtered_private_addrs = {
        if maybe_same_subnet {
            their_addrs
                .iter()
                .cloned()
                .filter(|addr| addr.ip().is_private())
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        }
    };
    let any_private_ips_in_common = {
        their_filtered_private_addrs
            .iter()
            .any(|a0| our_private_addrs.iter().any(|a1| a0.ip() == a1.ip()))
    };
    let maybe_same_machine = any_private_ips_in_common
        || (their_filtered_private_addrs.is_empty()
            && our_private_addrs.is_empty()
            && maybe_same_subnet);
    let their_filtered_loopback_addr = {
        if maybe_same_machine {
            their_addrs
                .iter()
                .cloned()
                .find(|addr| addr.ip().is_loopback())
        } else {
            None
        }
    };

    their_global_addrs
        .into_iter()
        .chain({
            their_filtered_private_addrs
                .into_iter()
                .chain(their_filtered_loopback_addr)
        })
        .collect()
}
