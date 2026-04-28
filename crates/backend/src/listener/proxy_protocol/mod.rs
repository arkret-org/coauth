mod acceptor;
mod maybe;
mod v1;

pub use self::{
    acceptor::{ProxyAcceptError, ProxyAcceptor},
    maybe::MaybeProxyAcceptor,
    v1::ProxyProtocolV1Info,
};
