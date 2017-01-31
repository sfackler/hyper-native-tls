//! SSL support for Hyper via the native-tls crate.
//!
//! # Usage
//!
//! On the client side:
//!
//! ```
//! extern crate hyper;
//! extern crate hyper_native_tls;
//!
//! use hyper::Client;
//! use hyper::net::HttpsConnector;
//! use hyper_native_tls::NativeTlsClient;
//! use std::io::Read;
//!
//! fn main() {
//!     let ssl = NativeTlsClient::new().unwrap();
//!     let connector = HttpsConnector::new(ssl);
//!     let client = Client::with_connector(connector);
//!
//!     let mut resp = client.get("https://google.com").send().unwrap();
//!     let mut body = vec![];
//!     resp.read_to_end(&mut body).unwrap();
//!     println!("{}", String::from_utf8_lossy(&body));
//! }
//! ```
//!
//! Or on the server side:
//!
//! ```no_run
//! extern crate hyper;
//! extern crate hyper_native_tls;
//!
//! use hyper::Server;
//! use hyper_native_tls::NativeTlsServer;
//!
//! fn main() {
//!     let ssl = NativeTlsServer::new("identity.p12", "mypass").unwrap();
//!     let server = Server::https("0.0.0.0:8443", ssl).unwrap();
//! }
//! ```
#![warn(missing_docs)]
#![doc(html_root_url="https://docs.rs/hyper-native-tls/0.2.1")]
extern crate antidote;
extern crate hyper;
pub extern crate native_tls;

#[cfg(test)]
extern crate hyper_openssl;
#[cfg(test)]
extern crate openssl;

use antidote::Mutex;
use hyper::net::{SslClient, SslServer, NetworkStream};
use native_tls::{TlsAcceptor, TlsConnector, Pkcs12};
use std::net::SocketAddr;
use std::time::Duration;
use std::error::Error;
use std::io::{self, Read};
use std::fs::File;
use std::sync::Arc;
use std::fmt;
use std::path::Path;

/// A Hyper stream using native_tls.
#[derive(Debug, Clone)]
pub struct TlsStream<S>(Arc<Mutex<native_tls::TlsStream<S>>>);

impl<S> io::Read for TlsStream<S>
    where S: io::Read + io::Write
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buf)
    }
}

impl<S> io::Write for TlsStream<S>
    where S: io::Read + io::Write
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().flush()
    }
}

impl<S> NetworkStream for TlsStream<S>
    where S: NetworkStream
{
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.0.lock().get_mut().peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().get_mut().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().get_mut().set_write_timeout(dur)
    }
}

/// An `SslClient` implementation using native-tls.
pub struct NativeTlsClient(TlsConnector);

impl NativeTlsClient {
    /// Returns a `NativeTlsClient` with a default configuration.
    pub fn new() -> native_tls::Result<NativeTlsClient> {
        TlsConnector::builder().and_then(|b| b.build()).map(NativeTlsClient)
    }
}

impl From<TlsConnector> for NativeTlsClient {
    fn from(t: TlsConnector) -> NativeTlsClient {
        NativeTlsClient(t)
    }
}

impl<T> SslClient<T> for NativeTlsClient
    where T: NetworkStream + Send + Clone + fmt::Debug + Sync
{
    type Stream = TlsStream<T>;

    fn wrap_client(&self, stream: T, host: &str) -> hyper::Result<TlsStream<T>> {
        match self.0.connect(host, stream) {
            Ok(s) => Ok(TlsStream(Arc::new(Mutex::new(s)))),
            Err(e) => Err(hyper::Error::Ssl(Box::new(e))),
        }
    }
}

/// An `SslServer` implementation using native-tls.
#[derive(Clone)]
pub struct NativeTlsServer(Arc<TlsAcceptor>);

impl NativeTlsServer {
    /// Returns a `NativeTlsServer` with a default configuration.
    pub fn new<P>(identity: P, password: &str) -> Result<NativeTlsServer, ServerError>
        where P: AsRef<Path>
    {
        let mut buf = vec![];
        try!(File::open(identity)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(ServerError::Io));
        let identity = try!(Pkcs12::from_der(&buf, password).map_err(ServerError::Tls));

        let acceptor = try!(TlsAcceptor::builder(identity)
            .and_then(|b| b.build())
            .map_err(ServerError::Tls));
        Ok(acceptor.into())
    }
}

impl From<TlsAcceptor> for NativeTlsServer {
    fn from(t: TlsAcceptor) -> NativeTlsServer {
        NativeTlsServer(Arc::new(t))
    }
}

impl<T> SslServer<T> for NativeTlsServer
    where T: NetworkStream + Send + Clone + fmt::Debug + Sync
{
    type Stream = TlsStream<T>;

    fn wrap_server(&self, stream: T) -> hyper::Result<TlsStream<T>> {
        match self.0.accept(stream) {
            Ok(s) => Ok(TlsStream(Arc::new(Mutex::new(s)))),
            Err(e) => Err(hyper::Error::Ssl(Box::new(e))),
        }
    }
}

/// An error creating a `NativeTlsServer`.
#[derive(Debug)]
pub enum ServerError {
    /// An error reading the identity file.
    Io(io::Error),
    /// An error initializing the acceptor.
    Tls(native_tls::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        match *self {
            ServerError::Io(ref e) => write!(fmt, ": {}", e),
            ServerError::Tls(ref e) => write!(fmt, ": {}", e),
        }
    }
}

impl Error for ServerError {
    fn description(&self) -> &str {
        match *self {
            ServerError::Io(_) => "error reading identity",
            ServerError::Tls(_) => "error initializing acceptor",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            ServerError::Io(ref e) => Some(e),
            ServerError::Tls(ref e) => Some(e),
        }
    }
}

#[cfg(test)]
mod test {
    use hyper::{Client, Server};
    use hyper::server::{Request, Response, Fresh};
    use hyper::net::HttpsConnector;
    use hyper_openssl::OpensslClient;
    use openssl::ssl::{SslMethod, SslConnectorBuilder};
    use std::io::Read;
    use std::mem;

    use super::*;

    #[test]
    fn client() {
        let ssl = NativeTlsClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let mut resp = client.get("https://google.com").send().unwrap();
        assert!(resp.status.is_success());
        let mut body = vec![];
        resp.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn server() {
        let ssl = NativeTlsServer::new("test/identity.p12", "mypass").unwrap();
        let server = Server::https("127.0.0.1:0", ssl).unwrap();

        let listening = server.handle(|_: Request, resp: Response<Fresh>| {
            resp.send(b"hello").unwrap()
        }).unwrap();
        let port = listening.socket.port();
        mem::forget(listening);

        let mut ssl = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
        ssl.builder_mut().set_ca_file("test/root-ca.pem").unwrap();
        let ssl = OpensslClient::from(ssl.build());
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let mut resp = client.get(&format!("https://localhost:{}", port)).send().unwrap();
        let mut body = vec![];
        resp.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"hello");
    }
}
